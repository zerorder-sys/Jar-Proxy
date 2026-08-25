package com.jarproxy;

import io.netty.buffer.ByteBuf;
import io.netty.channel.*;

/**
 * Bidirectional TCP relay handler. Reads data from one channel and writes
 * it to the other. Used after SOCKS5 CONNECT is established.
 */
public class TcpRelay extends SimpleChannelInboundHandler<ByteBuf> {

    private final Channel targetChannel;
    private final String label;

    public TcpRelay(Channel targetChannel, String label) {
        this.targetChannel = targetChannel;
        this.label = label;
    }

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, ByteBuf msg) {
        if (targetChannel.isActive()) {
            targetChannel.writeAndFlush(msg.retain());
        }
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) {
        closeOnFlush(targetChannel);
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        ProxyLogger.debug("Relay error [" + label + "]: " + cause.getMessage());
        closeOnFlush(ctx.channel());
    }

    private static void closeOnFlush(Channel ch) {
        if (ch.isActive()) {
            ch.writeAndFlush(io.netty.buffer.Unpooled.EMPTY_BUFFER)
                .addListener(ChannelFutureListener.CLOSE);
        }
    }
}
