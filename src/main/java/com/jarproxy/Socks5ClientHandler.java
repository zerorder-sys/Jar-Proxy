package com.jarproxy;

import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.*;
import io.netty.channel.*;
import io.netty.util.ReferenceCounted;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.util.CharsetUtil;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

/**
 * Handles the full SOCKS5 protocol state machine:
 * greeting -> auth -> command -> relay
 *
 * Uses ChannelInboundHandlerAdapter (not SimpleChannelInboundHandler) because
 * clients like curl send greeting+auth in a single TCP segment. The adapter lets
 * us retain the buffer and loop through protocol states without data loss.
 */
public class Socks5ClientHandler extends ChannelInboundHandlerAdapter {

    private static final int SOCKS5_VERSION = 0x05;
    private static final int AUTH_NONE = 0x00;
    private static final int AUTH_PASSWORD = 0x02;
    private static final int CMD_CONNECT = 0x01;
    private static final int CMD_UDP_ASSOCIATE = 0x03;
    private static final int ATYP_IPV4 = 0x01;
    private static final int ATYP_DOMAIN = 0x03;
    private static final int ATYP_IPV6 = 0x04;
    private static final int REP_SUCCESS = 0x00;
    private static final int REP_GENERAL_FAILURE = 0x01;
    private static final int REP_NOT_ALLOWED = 0x02;
    private static final int REP_HOST_UNREACHABLE = 0x04;
    private static final int REP_CONNECTION_REFUSED = 0x05;
    private static final int REP_COMMAND_NOT_SUPPORTED = 0x07;
    private static final int REP_ADDRESS_TYPE_NOT_SUPPORTED = 0x08;
    private static final int MAX_HOSTNAME_LENGTH = 255;

    private enum State { GREETING, AUTH, COMMAND, DONE }

    private final Config.ConfigData config;
    private final ConnectionLimiter limiter;
    private final AuthenticationManager authManager;
    private State state = State.GREETING;
    private String connectionId;
    private String clientAddr;

    public Socks5ClientHandler(Config.ConfigData config, ConnectionLimiter limiter, AuthenticationManager authManager) {
        this.config = config;
        this.limiter = limiter;
        this.authManager = authManager;
    }

    @Override
    public void channelActive(ChannelHandlerContext ctx) {
        connectionId = UUID.randomUUID().toString().substring(0, 8);
        clientAddr = ctx.channel().remoteAddress().toString();
        if (!limiter.canAcceptTcp()) {
            ProxyLogger.warn("Connection limit reached, rejecting: " + clientAddr);
            ctx.close();
            return;
        }
        limiter.trackTcp(connectionId);
    }

    private volatile boolean closed = false;

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) {
        if (closed) {
            if (msg instanceof ReferenceCounted rc) rc.release();
            return;
        }
        ProxyLogger.debug("channelRead from " + clientAddr + ": type=" + msg.getClass().getSimpleName()
            + " readable=" + (msg instanceof ByteBuf b ? b.readableBytes() : "N/A") + " state=" + state);
        if (msg instanceof ByteBuf buf) {
            while (buf.isReadable() && state != State.DONE && !closed) {
                switch (state) {
                    case GREETING -> handleGreeting(ctx, buf);
                    case AUTH -> handleAuth(ctx, buf);
                    case COMMAND -> handleCommand(ctx, buf);
                    default -> { return; }
                }
            }
        }
        if (msg instanceof ReferenceCounted rc) {
            rc.release();
        }
    }

    /**
     * SOCKS5 greeting: [VER, NMETHODS, METHODS...]
     */
    private void handleGreeting(ChannelHandlerContext ctx, ByteBuf buf) {
        if (buf.readableBytes() < 3) {
            sendErrorAndClose(ctx, "Short greeting");
            return;
        }
        int version = buf.readByte() & 0xFF;
        if (version != SOCKS5_VERSION) {
            sendErrorAndClose(ctx, "Invalid SOCKS5 version: " + version);
            return;
        }
        int nMethods = buf.readByte() & 0xFF;
        if (buf.readableBytes() < nMethods) {
            sendErrorAndClose(ctx, "Incomplete methods list");
            return;
        }
        buf.skipBytes(nMethods);

        ByteBuf response = ctx.alloc().buffer(2);
        response.writeByte(SOCKS5_VERSION);

        if (authManager.isEnabled()) {
            response.writeByte(AUTH_PASSWORD);
            state = State.AUTH;
        } else {
            response.writeByte(AUTH_NONE);
            state = State.COMMAND;
        }

        ctx.writeAndFlush(response);
    }

    /**
     * Username/password auth (RFC 1929): [VER, ULEN, UNAME, PLEN, PASSWD]
     */
    private void handleAuth(ChannelHandlerContext ctx, ByteBuf buf) {
        if (buf.readableBytes() < 2) {
            sendErrorAndClose(ctx, "Short auth packet");
            return;
        }
        int version = buf.readByte() & 0xFF;
        if (version != 0x01) {
            sendErrorAndClose(ctx, "Invalid auth version: " + version);
            return;
        }

        int uLen = buf.readByte() & 0xFF;
        if (buf.readableBytes() < uLen + 1) {
            sendErrorAndClose(ctx, "Short username in auth");
            return;
        }
        String username = buf.readSlice(uLen).toString(CharsetUtil.UTF_8);

        int pLen = buf.readByte() & 0xFF;
        if (buf.readableBytes() < pLen) {
            sendErrorAndClose(ctx, "Short password in auth");
            return;
        }
        String password = buf.readSlice(pLen).toString(CharsetUtil.UTF_8);

        ProxyLogger.connection("Auth attempt from " + clientAddr + " user=" + username);

        boolean authenticated = authManager.authenticate(username, password);

        ByteBuf response = ctx.alloc().buffer(2);
        response.writeByte(0x01);
        response.writeByte(authenticated ? 0x00 : 0x01);

        if (!authenticated) {
            ProxyLogger.authFailure("Auth FAILED from " + clientAddr + " user=" + username);
            ctx.writeAndFlush(response).addListener(ChannelFutureListener.CLOSE);
            state = State.DONE;
            return;
        }

        ProxyLogger.connection("Auth OK from " + clientAddr + " user=" + username);
        state = State.COMMAND;
        ctx.writeAndFlush(response);
    }

    /**
     * SOCKS5 command: [VER, CMD, RSV, ATYP, DST.ADDR, DST.PORT]
     */
    private void handleCommand(ChannelHandlerContext ctx, ByteBuf buf) {
        if (buf.readableBytes() < 4) {
            sendErrorAndClose(ctx, "Short command");
            return;
        }

        int version = buf.readByte() & 0xFF;
        if (version != SOCKS5_VERSION) {
            sendCommandReply(ctx, REP_GENERAL_FAILURE);
            state = State.DONE;
            return;
        }

        int cmd = buf.readByte() & 0xFF;
        buf.readByte(); // RSV
        int atyp = buf.readByte() & 0xFF;

        String dstAddr;
        int dstPort;
        byte[] addrBytes;

        try {
            switch (atyp) {
                case ATYP_IPV4 -> {
                    if (buf.readableBytes() < 4) { sendCommandReply(ctx, REP_GENERAL_FAILURE); state = State.DONE; return; }
                    addrBytes = new byte[4];
                    buf.readBytes(addrBytes);
                    dstAddr = String.format("%d.%d.%d.%d",
                        addrBytes[0] & 0xFF, addrBytes[1] & 0xFF,
                        addrBytes[2] & 0xFF, addrBytes[3] & 0xFF);
                }
                case ATYP_DOMAIN -> {
                    if (buf.readableBytes() < 1) { sendCommandReply(ctx, REP_GENERAL_FAILURE); state = State.DONE; return; }
                    int domainLen = buf.readByte() & 0xFF;
                    if (domainLen > MAX_HOSTNAME_LENGTH) {
                        sendCommandReply(ctx, REP_GENERAL_FAILURE);
                        state = State.DONE;
                        return;
                    }
                    if (buf.readableBytes() < domainLen) { sendCommandReply(ctx, REP_GENERAL_FAILURE); state = State.DONE; return; }
                    dstAddr = buf.readSlice(domainLen).toString(CharsetUtil.US_ASCII);
                }
                case ATYP_IPV6 -> {
                    if (buf.readableBytes() < 16) { sendCommandReply(ctx, REP_GENERAL_FAILURE); state = State.DONE; return; }
                    addrBytes = new byte[16];
                    buf.readBytes(addrBytes);
                    dstAddr = String.format("[%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x]",
                        addrBytes[0] & 0xFF, addrBytes[1] & 0xFF, addrBytes[2] & 0xFF, addrBytes[3] & 0xFF,
                        addrBytes[4] & 0xFF, addrBytes[5] & 0xFF, addrBytes[6] & 0xFF, addrBytes[7] & 0xFF,
                        addrBytes[8] & 0xFF, addrBytes[9] & 0xFF, addrBytes[10] & 0xFF, addrBytes[11] & 0xFF,
                        addrBytes[12] & 0xFF, addrBytes[13] & 0xFF, addrBytes[14] & 0xFF, addrBytes[15] & 0xFF);
                }
                default -> {
                    sendCommandReply(ctx, REP_ADDRESS_TYPE_NOT_SUPPORTED);
                    state = State.DONE;
                    return;
                }
            }
        } catch (Exception e) {
            sendCommandReply(ctx, REP_GENERAL_FAILURE);
            state = State.DONE;
            return;
        }

        if (buf.readableBytes() < 2) { sendCommandReply(ctx, REP_GENERAL_FAILURE); state = State.DONE; return; }
        dstPort = buf.readShort() & 0xFFFF;

        ProxyLogger.destination("CMD=" + cmd + " dst=" + dstAddr + ":" + dstPort + " from=" + clientAddr);

        state = State.DONE; // Prevent further processing on this handler

        switch (cmd) {
            case CMD_CONNECT -> handleConnect(ctx, atyp, dstAddr, dstPort);
            case CMD_UDP_ASSOCIATE -> handleUdpAssociate(ctx);
            default -> sendCommandReply(ctx, REP_COMMAND_NOT_SUPPORTED);
        }
    }

    private void handleConnect(ChannelHandlerContext ctx, int atyp, String dstAddr, int dstPort) {
        ProxyLogger.connection("TCP CONNECT " + dstAddr + ":" + dstPort + " from " + clientAddr);

        Bootstrap bootstrap = new Bootstrap();
        bootstrap.group(ctx.channel().eventLoop())
            .channel(NioSocketChannel.class)
            .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, config.timeouts().connection())
            .handler(new ChannelInitializer<SocketChannel>() {
                @Override
                protected void initChannel(SocketChannel ch) {}
            });

        ChannelFuture connectFuture;
        if (atyp == ATYP_DOMAIN) {
            try {
                InetAddress[] addresses = InetAddress.getAllByName(dstAddr);
                connectFuture = bootstrap.connect(addresses[0], dstPort);
            } catch (Exception e) {
                sendCommandReply(ctx, REP_HOST_UNREACHABLE);
                return;
            }
        } else {
            connectFuture = bootstrap.connect(dstAddr, dstPort);
        }

        connectFuture.addListener((ChannelFutureListener) future -> {
            if (future.isSuccess()) {
                Channel targetChannel = future.channel();
                sendCommandReply(ctx, REP_SUCCESS);

                Channel clientChannel = ctx.channel();
                targetChannel.pipeline().addLast(new TcpRelay(clientChannel, "target->client"));
                clientChannel.pipeline().addLast(new TcpRelay(targetChannel, "client->target"));
                clientChannel.pipeline().remove(this);

                ProxyLogger.connection("TCP CONNECT established to " + dstAddr + ":" + dstPort);
            } else {
                int reply;
                if (future.cause() instanceof java.net.ConnectException ce) {
                    String msg = ce.getMessage();
                    reply = (msg != null && msg.contains("Connection refused"))
                        ? REP_CONNECTION_REFUSED : REP_HOST_UNREACHABLE;
                } else {
                    reply = REP_HOST_UNREACHABLE;
                }
                sendCommandReply(ctx, reply);
            }
        });
    }

    private void handleUdpAssociate(ChannelHandlerContext ctx) {
        if (!config.network().udp().enabled()) {
            sendCommandReply(ctx, REP_COMMAND_NOT_SUPPORTED);
            return;
        }

        if (!limiter.canAcceptUdp()) {
            sendCommandReply(ctx, REP_NOT_ALLOWED);
            return;
        }

        String udpId = limiter.trackUdp(connectionId);
        if (udpId == null) {
            sendCommandReply(ctx, REP_NOT_ALLOWED);
            return;
        }

        ProxyLogger.connection("UDP ASSOCIATE requested from " + clientAddr);

        UdpAssociate udpRelay = new UdpAssociate(
            ctx.channel(), config, limiter, connectionId
        );

        udpRelay.start(
            udpBindAddr -> {
                sendBindReply(ctx, REP_SUCCESS, udpBindAddr);
                ProxyLogger.connection("UDP ASSOCIATE bound on " + udpBindAddr);

                ctx.channel().closeFuture().addListener(f -> {
                    udpRelay.stop();
                    limiter.releaseUdp(udpId);
                    ProxyLogger.connection("UDP ASSOCIATE closed for " + clientAddr);
                });
            },
            error -> {
                limiter.releaseUdp(udpId);
                ProxyLogger.error("Failed to create UDP ASSOCIATE: " + error.getMessage());
                sendCommandReply(ctx, REP_GENERAL_FAILURE);
            }
        );
    }

    private void sendCommandReply(ChannelHandlerContext ctx, int rep) {
        ByteBuf reply = ctx.alloc().buffer(10);
        reply.writeByte(SOCKS5_VERSION);
        reply.writeByte(rep);
        reply.writeByte(0x00);
        reply.writeByte(ATYP_IPV4);
        reply.writeBytes(new byte[]{0, 0, 0, 0});
        reply.writeShort(0);
        ctx.writeAndFlush(reply);
    }

    private void sendBindReply(ChannelHandlerContext ctx, int rep, InetSocketAddress addr) {
        ByteBuf reply = ctx.alloc().buffer(10);
        reply.writeByte(SOCKS5_VERSION);
        reply.writeByte(rep);
        reply.writeByte(0x00);

        if (addr.getAddress() instanceof java.net.Inet6Address) {
            reply.writeByte(ATYP_IPV6);
            reply.writeBytes(addr.getAddress().getAddress());
        } else {
            reply.writeByte(ATYP_IPV4);
            reply.writeBytes(addr.getAddress().getAddress());
        }
        reply.writeShort(addr.getPort());
        ctx.writeAndFlush(reply);
    }

    private void sendErrorAndClose(ChannelHandlerContext ctx, String reason) {
        closed = true;
        ProxyLogger.warn("Protocol error from " + clientAddr + ": " + reason);
        ctx.close();
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        ProxyLogger.warn("Exception from " + clientAddr + ": " + cause.getClass().getSimpleName() + ": " + cause.getMessage());
        ctx.close();
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) {
        if (connectionId != null) {
            limiter.releaseTcp(connectionId);
        }
        ProxyLogger.connection("Client disconnected: " + clientAddr);
    }

    @Override
    public void userEventTriggered(ChannelHandlerContext ctx, Object evt) throws Exception {
        if (evt instanceof io.netty.handler.timeout.IdleStateEvent) {
            ProxyLogger.debug("Idle timeout for " + clientAddr);
            ctx.close();
        } else {
            super.userEventTriggered(ctx, evt);
        }
    }
}
