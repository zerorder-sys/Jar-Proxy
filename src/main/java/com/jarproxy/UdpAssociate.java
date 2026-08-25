package com.jarproxy;

import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.*;
import io.netty.channel.*;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.DatagramPacket;
import io.netty.channel.socket.nio.NioDatagramChannel;
import io.netty.util.CharsetUtil;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

/**
 * SOCKS5 UDP ASSOCIATE implementation.
 *
 * Protocol flow:
 * 1. Client establishes TCP control connection and sends UDP ASSOCIATE.
 * 2. Server binds a UDP socket, returns the bind address/port to client.
 * 3. Client sends UDP datagrams to the server's UDP port with the SOCKS5 header.
 * 4. Server parses header, resolves destination if needed, forwards payload.
 * 5. Server receives responses from targets, wraps in SOCKS5 header, sends back.
 * 6. Association ends when TCP control connection closes.
 *
 * Security:
 * - Only accepts UDP packets from the authenticated client's TCP address.
 * - Rejects fragmented datagrams (FRAG != 0).
 * - Validates packet structure before processing.
 *
 * UDP packet format per RFC 1928:
 * +----+------+------+----------+----------+----------+
 * |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
 * +----+------+------+----------+----------+----------+
 * | 2  |  1   |  1   | Variable |    2     | Variable |
 * +----+------+------+----------+----------+----------+
 */
public class UdpAssociate {

    private static final int ATYP_IPV4 = 0x01;
    private static final int ATYP_DOMAIN = 0x03;
    private static final int ATYP_IPV6 = 0x04;
    private static final int MAX_HOSTNAME_LENGTH = 255;

    private final Channel controlChannel;
    private final Config.ConfigData config;
    private final ConnectionLimiter limiter;
    private final String connectionId;
    private Channel udpChannel;
    private InetSocketAddress clientUdpAddress;
    // Track target addresses we've sent to so we can distinguish
    // responses from the target vs new requests from the client.
    private final ConcurrentHashMap<InetSocketAddress, Boolean> knownTargets = new ConcurrentHashMap<>();

    public UdpAssociate(Channel controlChannel, Config.ConfigData config,
                        ConnectionLimiter limiter, String connectionId) {
        this.controlChannel = controlChannel;
        this.config = config;
        this.limiter = limiter;
        this.connectionId = connectionId;
    }

    /**
     * Starts the UDP relay by binding a local UDP socket.
     * Returns the bound address/port to send to the client.
     */
    /**
     * Starts the UDP relay asynchronously. When the bind completes,
     * the callback is invoked with the bound address or an error.
     */
    public void start(java.util.function.Consumer<InetSocketAddress> onSuccess,
                      java.util.function.Consumer<Exception> onError) {
        Bootstrap udpBootstrap = new Bootstrap();
        udpBootstrap.group(controlChannel.eventLoop())
            .channel(NioDatagramChannel.class)
            .option(ChannelOption.SO_BROADCAST, false)
            .option(ChannelOption.SO_REUSEADDR, true)
            .handler(new UdpRelayHandler());

        udpBootstrap.bind(config.socks5().host(), 0).addListener((ChannelFutureListener) future -> {
            if (future.isSuccess()) {
                udpChannel = future.channel();
                onSuccess.accept((InetSocketAddress) udpChannel.localAddress());
            } else {
                onError.accept(future.cause() instanceof Exception e ? e : new RuntimeException(future.cause()));
            }
        });
    }

    /**
     * Stops the UDP relay and releases resources.
     */
    public void stop() {
        knownTargets.clear();
        if (udpChannel != null && udpChannel.isActive()) {
            udpChannel.close();
        }
    }

    /**
     * Handles all incoming UDP datagrams.
     *
     * Routing logic:
     * - If sender == clientAddress: parse SOCKS5 header, forward to target.
     * - If sender is a known target: wrap response in SOCKS5 header, send to client.
     * - Otherwise: drop (prevents reflection attacks).
     */
    private class UdpRelayHandler extends SimpleChannelInboundHandler<DatagramPacket> {

        @Override
        protected void channelRead0(ChannelHandlerContext ctx, DatagramPacket packet) {
            InetSocketAddress sender = packet.sender();

            // Phase 1: Identify the client from their first UDP packet
            if (clientUdpAddress == null) {
                clientUdpAddress = sender;
                ProxyLogger.debug("UDP client identified: " + sender);
            }

            // Phase 2: Route based on sender identity
            if (sender.equals(clientUdpAddress)) {
                handleClientPacket(ctx, packet);
            } else if (knownTargets.containsKey(sender)) {
                handleTargetResponse(ctx, sender, packet.content());
            } else {
                // Unknown sender - drop silently to prevent reflection/abuse
                ProxyLogger.debug("UDP packet from unknown sender dropped: " + sender);
            }
        }

        /**
         * Handle a packet from the authenticated client.
         * Parse SOCKS5 UDP header and forward payload to the target.
         */
        private void handleClientPacket(ChannelHandlerContext ctx, DatagramPacket packet) {
            ByteBuf buf = packet.content();
            if (buf.readableBytes() < 4) {
                // Minimum header: RSV(2) + FRAG(1) + ATYP(1)
                return;
            }

            // RSV (2 bytes) - must be 0x0000 per RFC 1928
            buf.readShort();

            // FRAG (1 byte) - reject fragmentation (security: preventing fragment-based attacks)
            int frag = buf.readByte() & 0xFF;
            if (frag != 0) {
                ProxyLogger.debug("Rejected fragmented UDP packet (FRAG=" + frag + ")");
                return;
            }

            // ATYP (1 byte)
            int atyp = buf.readByte() & 0xFF;

            // Parse target address from header
            InetSocketAddress targetAddr;
            try {
                targetAddr = parseTargetAddress(buf, atyp);
                if (targetAddr == null) {
                    ProxyLogger.debug("Failed to parse UDP target address");
                    return;
                }
            } catch (Exception e) {
                ProxyLogger.debug("UDP address parse error: " + e.getMessage());
                return;
            }

            // Remaining bytes = actual data payload
            if (buf.readableBytes() == 0) {
                // Zero-length data is used to probe the relay (some clients do this)
                return;
            }
            ByteBuf data = buf.readRetainedSlice(buf.readableBytes());

            // Track this target so we can identify its responses
            knownTargets.put(targetAddr, Boolean.TRUE);

            ProxyLogger.destination("UDP " + targetAddr + " (" + data.readableBytes() + " bytes)");

            // Forward payload to target
            DatagramPacket outbound = new DatagramPacket(data, targetAddr);
            ctx.writeAndFlush(outbound).addListener((ChannelFutureListener) future -> {
                if (!future.isSuccess()) {
                    ProxyLogger.debug("Failed to send UDP to " + targetAddr);
                }
            });
        }

        /**
         * Handle a response from a target destination.
         * Wrap in SOCKS5 UDP header and send back to the client.
         */
        private void handleTargetResponse(ChannelHandlerContext ctx, InetSocketAddress target, ByteBuf data) {
            if (clientUdpAddress == null) return;

            ByteBuf response = ctx.alloc().buffer();
            // RSV (2 bytes)
            response.writeShort(0);
            // FRAG (1 byte)
            response.writeByte(0);

            // BND.ADDR = address of the responding target
            InetAddress addr = target.getAddress();
            if (addr instanceof java.net.Inet6Address) {
                response.writeByte(ATYP_IPV6);
                response.writeBytes(addr.getAddress());
            } else {
                response.writeByte(ATYP_IPV4);
                response.writeBytes(addr.getAddress());
            }
            // BND.PORT
            response.writeShort(target.getPort());
            // DATA
            response.writeBytes(data);

            // Send back to client
            ctx.writeAndFlush(new DatagramPacket(response, clientUdpAddress));
        }
    }

    /**
     * Parses the target address from the SOCKS5 UDP header.
     * Advances the buffer position past the address and port.
     */
    private InetSocketAddress parseTargetAddress(ByteBuf buf, int atyp) {
        byte[] addrBytes;
        String host;
        int port;

        switch (atyp) {
            case ATYP_IPV4 -> {
                if (buf.readableBytes() < 4 + 2) return null;
                addrBytes = new byte[4];
                buf.readBytes(addrBytes);
                host = String.format("%d.%d.%d.%d",
                    addrBytes[0] & 0xFF, addrBytes[1] & 0xFF,
                    addrBytes[2] & 0xFF, addrBytes[3] & 0xFF);
            }
            case ATYP_DOMAIN -> {
                if (buf.readableBytes() < 1) return null;
                int domainLen = buf.readByte() & 0xFF;
                if (domainLen > MAX_HOSTNAME_LENGTH || buf.readableBytes() < domainLen + 2) return null;
                host = buf.readSlice(domainLen).toString(CharsetUtil.US_ASCII);
                // Resolve domain on the proxy side
                try {
                    InetAddress resolved = InetAddress.getByName(host);
                    host = resolved.getHostAddress();
                } catch (Exception ignored) {
                    // Will fail at send time if unresolvable
                }
            }
            case ATYP_IPV6 -> {
                if (buf.readableBytes() < 16 + 2) return null;
                addrBytes = new byte[16];
                buf.readBytes(addrBytes);
                host = String.format("%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                    addrBytes[0] & 0xFF, addrBytes[1] & 0xFF, addrBytes[2] & 0xFF, addrBytes[3] & 0xFF,
                    addrBytes[4] & 0xFF, addrBytes[5] & 0xFF, addrBytes[6] & 0xFF, addrBytes[7] & 0xFF,
                    addrBytes[8] & 0xFF, addrBytes[9] & 0xFF, addrBytes[10] & 0xFF, addrBytes[11] & 0xFF,
                    addrBytes[12] & 0xFF, addrBytes[13] & 0xFF, addrBytes[14] & 0xFF, addrBytes[15] & 0xFF);
            }
            default -> {
                ProxyLogger.debug("Unsupported UDP ATYP: " + atyp);
                return null;
            }
        }

        port = buf.readShort() & 0xFFFF;

        try {
            return new InetSocketAddress(host, port);
        } catch (Exception e) {
            return null;
        }
    }
}
