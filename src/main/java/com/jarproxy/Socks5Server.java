package com.jarproxy;

import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.*;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.handler.timeout.IdleStateHandler;
import java.util.concurrent.TimeUnit;

public class Socks5Server {
    private final Config.ConfigData config;
    private final EventLoopGroup workerGroup;
    private Channel serverChannel;
    private final ConnectionLimiter limiter;
    private final AuthenticationManager authManager;

    public Socks5Server(Config.ConfigData config, EventLoopGroup workerGroup) {
        this.config = config;
        this.workerGroup = workerGroup;
        this.limiter = new ConnectionLimiter(config.limits());
        this.authManager = new AuthenticationManager(config.authentication());
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
                            config.timeouts().connection(),
                            0,
                            config.timeouts().idle(),
                            TimeUnit.MILLISECONDS
                        ),
                        new Socks5ClientHandler(config, limiter, authManager)
                    );
                }
            });

        ChannelFuture future = bootstrap.bind(config.socks5().host(), config.socks5().port()).sync();
        serverChannel = future.channel();
    }

    public void stop() {
        if (serverChannel != null) {
            serverChannel.close();
        }
    }

    public int getPort() {
        return serverChannel != null ? ((java.net.InetSocketAddress) serverChannel.localAddress()).getPort() : -1;
    }

    public ConnectionLimiter getLimiter() {
        return limiter;
    }

    public AuthenticationManager getAuthManager() {
        return authManager;
    }
}
