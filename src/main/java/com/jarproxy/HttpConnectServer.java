package com.jarproxy;

import io.netty.bootstrap.Bootstrap;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.buffer.*;
import io.netty.channel.*;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.timeout.IdleStateHandler;
import io.netty.util.CharsetUtil;
import io.netty.util.ReferenceCounted;
import java.net.InetSocketAddress;
import java.util.Base64;
import java.util.concurrent.TimeUnit;

/**
 * Optional HTTP/1.1 CONNECT proxy.
 * Supports: CONNECT host:port HTTP/1.1
 *           GET/POST http://host/path HTTP/1.x (plain HTTP forwarding)
 *           Proxy-Authorization: Basic base64(user:pass)
 * Shares the same credentials as the SOCKS5 server.
 */
public class HttpConnectServer {
    private final Config.ConfigData config;
    private final EventLoopGroup workerGroup;
    private final AuthenticationManager authManager;
    private final ConnectionLimiter limiter;
    private Channel serverChannel;

    public HttpConnectServer(Config.ConfigData config, EventLoopGroup workerGroup) {
        this.config = config;
        this.workerGroup = workerGroup;
        this.authManager = new AuthenticationManager(config.authentication());
        this.limiter = new ConnectionLimiter(config.limits());
    }

    public void start() throws Exception {
        ServerBootstrap bootstrap = new ServerBootstrap();
        bootstrap.group(new io.netty.channel.nio.NioEventLoopGroup(1), workerGroup)
            .channel(NioServerSocketChannel.class)
            .option(ChannelOption.SO_BACKLOG, 128)
            .option(ChannelOption.SO_REUSEADDR, true)
            .childOption(ChannelOption.SO_KEEPALIVE, true)
            .childOption(ChannelOption.TCP_NODELAY, true)
            .childHandler(new ChannelInitializer<SocketChannel>() {
                @Override
                protected void initChannel(SocketChannel ch) {
                    ch.pipeline().addLast(
                        new IdleStateHandler(
                            config.timeouts().connection(), 0,
                            config.timeouts().idle(), TimeUnit.MILLISECONDS
                        ),
                        new HttpConnectHandler(config, authManager, limiter)
                    );
                }
            });

        ChannelFuture future = bootstrap.bind("0.0.0.0", config.http_proxy().port()).sync();
        serverChannel = future.channel();
    }

    public void stop() {
        if (serverChannel != null) serverChannel.close();
    }

    public int getServerPort() {
        return serverChannel != null ? ((InetSocketAddress) serverChannel.localAddress()).getPort() : -1;
    }

    /**
     * HTTP CONNECT handler using ChannelInboundHandlerAdapter for manual buffer control.
     * Handles both CONNECT (tunneling) and plain HTTP (GET/POST forwarding).
     */
    private static class HttpConnectHandler extends ChannelInboundHandlerAdapter {

        private final Config.ConfigData config;
        private final AuthenticationManager authManager;
        private final ConnectionLimiter limiter;
        private final StringBuilder headerBuf = new StringBuilder();
        private volatile boolean headerComplete = false;
        private volatile boolean closed = false;
        private Channel targetChannel;
        private String clientAddr;

        HttpConnectHandler(Config.ConfigData config, AuthenticationManager authManager, ConnectionLimiter limiter) {
            this.config = config;
            this.authManager = authManager;
            this.limiter = limiter;
        }

        @Override
        public void channelActive(ChannelHandlerContext ctx) {
            clientAddr = ctx.channel().remoteAddress().toString();
        }

        @Override
        public void channelRead(ChannelHandlerContext ctx, Object msg) {
            if (closed) {
                if (msg instanceof ReferenceCounted rc) rc.release();
                return;
            }

            if (headerComplete) {
                if (msg instanceof ByteBuf buf) {
                    if (targetChannel != null && targetChannel.isActive()) {
                        targetChannel.writeAndFlush(buf.retain());
                    } else {
                        buf.release();
                    }
                }
                return;
            }

            if (msg instanceof ByteBuf buf) {
                try {
                    int headerEndIdx = findHeaderEnd(buf);
                    if (headerEndIdx < 0) {
                        headerBuf.append(buf.toString(CharsetUtil.US_ASCII));
                        buf.release();

                        if (headerBuf.length() > 16384) {
                            ProxyLogger.warn("HTTP header too large from " + clientAddr);
                            closed = true;
                            ctx.close();
                        }
                        return;
                    }

                    String headerStr = buf.toString(buf.readerIndex(), headerEndIdx, CharsetUtil.US_ASCII);
                    buf.skipBytes(headerEndIdx);

                    headerComplete = true;

                    String[] lines = headerStr.split("\r\n");
                    if (lines.length == 0) {
                        buf.release();
                        sendError(ctx, "HTTP/1.1 400 Bad Request\r\n\r\n");
                        return;
                    }

                    String[] parts = lines[0].split("\\s+");
                    String method = parts[0].toUpperCase();

                    String authHeader = null;
                    for (int i = 1; i < lines.length; i++) {
                        if (lines[i].toLowerCase().startsWith("proxy-authorization:")) {
                            authHeader = lines[i].substring("proxy-authorization:".length()).trim();
                            break;
                        }
                    }

                    if (!authenticate(ctx, authHeader)) {
                        buf.release();
                        return;
                    }

                    if (method.equals("CONNECT")) {
                        handleConnect(ctx, parts, buf);
                    } else {
                        handlePlainHttp(ctx, parts, method, buf);
                    }
                } catch (Exception e) {
                    ProxyLogger.warn("HTTP handler error from " + clientAddr + ": " + e.getMessage());
                    if (msg instanceof ByteBuf b) b.release();
                    sendError(ctx, "HTTP/1.1 400 Bad Request\r\n\r\n");
                }
            }
        }

        private int findHeaderEnd(ByteBuf buf) {
            int readable = buf.readableBytes();
            int start = buf.readerIndex();
            for (int i = 0; i <= readable - 4; i++) {
                byte b0 = buf.getByte(start + i);
                byte b1 = buf.getByte(start + i + 1);
                byte b2 = buf.getByte(start + i + 2);
                byte b3 = buf.getByte(start + i + 3);
                if (b0 == '\r' && b1 == '\n' && b2 == '\r' && b3 == '\n') {
                    return i + 4;
                }
            }
            return -1;
        }

        private boolean authenticate(ChannelHandlerContext ctx, String authHeader) {
            if (!authManager.isEnabled()) return true;

            if (authHeader == null || !authHeader.toLowerCase().startsWith("basic ")) {
                ProxyLogger.authFailure("HTTP missing auth from " + clientAddr);
                sendError(ctx, "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"JarProxy\"\r\n\r\n");
                return false;
            }

            String base64Credentials = authHeader.substring(6).trim();
            String decoded;
            try {
                decoded = new String(Base64.getDecoder().decode(base64Credentials), CharsetUtil.UTF_8);
            } catch (IllegalArgumentException e) {
                sendError(ctx, "HTTP/1.1 407 Proxy Authentication Required\r\n\r\n");
                return false;
            }

            String[] creds = decoded.split(":", 2);
            if (creds.length != 2 || !authManager.authenticate(creds[0], creds[1])) {
                ProxyLogger.authFailure("HTTP auth failed from " + clientAddr + " user=" + creds[0]);
                sendError(ctx, "HTTP/1.1 407 Proxy Authentication Required\r\n\r\n");
                return false;
            }

            ProxyLogger.connection("HTTP auth OK user=" + creds[0] + " from " + clientAddr);
            return true;
        }

        private void handleConnect(ChannelHandlerContext ctx, String[] parts, ByteBuf remainingBuf) {
            if (parts.length < 2) {
                remainingBuf.release();
                sendError(ctx, "HTTP/1.1 400 Bad Request\r\n\r\n");
                return;
            }

            String target = parts[1];
            String[] hostPort = target.split(":");
            if (hostPort.length != 2) {
                remainingBuf.release();
                sendError(ctx, "HTTP/1.1 400 Bad Request\r\n\r\n");
                return;
            }

            String host = hostPort[0];
            int port;
            try {
                port = Integer.parseInt(hostPort[1]);
            } catch (NumberFormatException e) {
                remainingBuf.release();
                sendError(ctx, "HTTP/1.1 400 Bad Request\r\n\r\n");
                return;
            }

            ProxyLogger.connection("HTTP CONNECT " + host + ":" + port + " from " + clientAddr);

            connectToTarget(ctx, host, port, "HTTP/1.1 200 Connection Established\r\n\r\n", remainingBuf);
        }

        private void handlePlainHttp(ChannelHandlerContext ctx, String[] parts, String method, ByteBuf remainingBuf) {
            if (parts.length < 3) {
                remainingBuf.release();
                sendError(ctx, "HTTP/1.1 400 Bad Request\r\n\r\n");
                return;
            }

            String url = parts[1];
            String host;
            int port = 80;

            if (url.startsWith("http://")) {
                url = url.substring(7);
                int slashIdx = url.indexOf('/');
                String hostPort = slashIdx > 0 ? url.substring(0, slashIdx) : url;
                String[] hp = hostPort.split(":");
                host = hp[0];
                if (hp.length > 1) port = Integer.parseInt(hp[1]);
            } else {
                host = url;
            }

            ProxyLogger.connection("HTTP " + method + " " + host + ":" + port + " from " + clientAddr);

            String headers = headerBuf.toString();
            int headerEnd = headers.indexOf("\r\n\r\n");
            String headerSection = headerEnd >= 0 ? headers.substring(0, headerEnd) : headers;

            StringBuilder forwardHeaders = new StringBuilder();
            String[] lines = headerSection.split("\r\n");
            forwardHeaders.append(lines[0]).append("\r\n");
            for (int i = 1; i < lines.length; i++) {
                String line = lines[i];
                String lower = line.toLowerCase();
                if (lower.startsWith("proxy-authorization:") || lower.startsWith("proxy-connection:")) {
                    continue;
                }
                forwardHeaders.append(line).append("\r\n");
            }
            forwardHeaders.append("\r\n");

            byte[] headerBytes = forwardHeaders.toString().getBytes(CharsetUtil.US_ASCII);
            ByteBuf combined = Unpooled.buffer(headerBytes.length + remainingBuf.readableBytes());
            combined.writeBytes(headerBytes);
            combined.writeBytes(remainingBuf);
            remainingBuf.release();

            connectToTarget(ctx, host, port, null, combined);
        }

        private void connectToTarget(ChannelHandlerContext ctx, String host, int port, String connectResponse, ByteBuf initialData) {
            Bootstrap bootstrap = new Bootstrap();
            bootstrap.group(ctx.channel().eventLoop())
                .channel(NioSocketChannel.class)
                .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, config.timeouts().connection())
                .handler(new ChannelInitializer<SocketChannel>() {
                    @Override
                    protected void initChannel(SocketChannel ch) {}
                });

            ChannelFuture connectFuture = bootstrap.connect(host, port);
            connectFuture.addListener((ChannelFutureListener) future -> {
                if (future.isSuccess()) {
                    targetChannel = future.channel();

                    if (connectResponse != null) {
                        ctx.writeAndFlush(Unpooled.copiedBuffer(connectResponse, CharsetUtil.US_ASCII));
                    }

                    if (initialData != null && initialData.isReadable()) {
                        targetChannel.writeAndFlush(initialData);
                    } else if (initialData != null) {
                        initialData.release();
                    }

                    Channel clientChannel = ctx.channel();
                    targetChannel.pipeline().addLast(new TcpRelay(clientChannel, "http-target->client"));
                    clientChannel.pipeline().addLast(new TcpRelay(targetChannel, "http-client->target"));
                    clientChannel.pipeline().remove(this);

                    ProxyLogger.connection("HTTP tunnel established to " + host + ":" + port);
                } else {
                    if (initialData != null) initialData.release();
                    sendError(ctx, "HTTP/1.1 502 Bad Gateway\r\n\r\n");
                }
            });
        }

        private void sendError(ChannelHandlerContext ctx, String error) {
            closed = true;
            ctx.writeAndFlush(Unpooled.copiedBuffer(error, CharsetUtil.US_ASCII))
                .addListener(ChannelFutureListener.CLOSE);
        }

        @Override
        public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
            ProxyLogger.warn("HTTP proxy error from " + clientAddr + ": " + cause.getMessage());
            ctx.close();
        }

        @Override
        public void channelInactive(ChannelHandlerContext ctx) {
            ProxyLogger.debug("HTTP client disconnected: " + clientAddr);
        }
    }
}
