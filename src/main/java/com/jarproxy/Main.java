package com.jarproxy;

import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.*;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import java.util.concurrent.TimeUnit;

public class Main {
    private static EventLoopGroup bossGroup;
    private static EventLoopGroup workerGroup;
    private static Socks5Server socks5Server;
    private static HttpConnectServer httpServer;

    public static void main(String[] args) throws Exception {
        String configPath = args.length > 0 ? args[0] : "config.yml";
        Config.ConfigData config = Config.load(configPath);

        ProxyLogger.configure(config.logging());

        ProxyLogger.info("JarProxy starting...");
        if (config.socks5().enabled()) {
            ProxyLogger.info("SOCKS5 listening on " + config.socks5().host() + ":" + config.socks5().port());
        }
        ProxyLogger.info("Authentication: " + (config.authentication().enabled() ? "ENABLED" : "DISABLED"));
        ProxyLogger.info("TCP support: " + (config.network().tcp().enabled() ? "ENABLED" : "DISABLED"));
        ProxyLogger.info("UDP support: " + (config.network().udp().enabled() ? "ENABLED" : "DISABLED"));

        if (config.http_proxy().enabled()) {
            ProxyLogger.info("HTTP CONNECT proxy listening on " + config.http_proxy().port());
        }

        bossGroup = new NioEventLoopGroup(1);
        workerGroup = new NioEventLoopGroup();

        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            ProxyLogger.info("Shutting down...");
            shutdown();
            ProxyLogger.info("JarProxy stopped.");
        }));

        socks5Server = new Socks5Server(config, workerGroup);
        if (config.socks5().enabled()) {
            socks5Server.start();
        }

        if (config.http_proxy().enabled()) {
            httpServer = new HttpConnectServer(config, workerGroup);
            httpServer.start();
        }

        ProxyLogger.info("Ready for connections");
    }

    public static void shutdown() {
        try {
            if (socks5Server != null) socks5Server.stop();
            if (httpServer != null) httpServer.stop();
            if (workerGroup != null) workerGroup.shutdownGracefully(0, 5, TimeUnit.SECONDS).sync();
            if (bossGroup != null) bossGroup.shutdownGracefully(0, 5, TimeUnit.SECONDS).sync();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
