package com.jarproxy;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

public class ConnectionLimiter {
    private final int maxTcp;
    private final int maxUdp;
    private final AtomicInteger tcpCount = new AtomicInteger(0);
    private final AtomicInteger udpCount = new AtomicInteger(0);
    private final ConcurrentHashMap<String, Boolean> tcpConnections = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Boolean> udpAssociations = new ConcurrentHashMap<>();

    public ConnectionLimiter(Config.LimitConfig config) {
        this.maxTcp = config.max_connections();
        this.maxUdp = config.max_udp_associations();
    }

    public boolean canAcceptTcp() {
        return tcpCount.get() < maxTcp;
    }

    public boolean canAcceptUdp() {
        return udpCount.get() < maxUdp;
    }

    public String trackTcp(String id) {
        if (tcpCount.incrementAndGet() > maxTcp) {
            tcpCount.decrementAndGet();
            return null;
        }
        tcpConnections.put(id, Boolean.TRUE);
        return id;
    }

    public void releaseTcp(String id) {
        if (tcpConnections.remove(id) != null) {
            tcpCount.decrementAndGet();
        }
    }

    public String trackUdp(String id) {
        if (udpCount.incrementAndGet() > maxUdp) {
            udpCount.decrementAndGet();
            return null;
        }
        udpAssociations.put(id, Boolean.TRUE);
        return id;
    }

    public void releaseUdp(String id) {
        if (udpAssociations.remove(id) != null) {
            udpCount.decrementAndGet();
        }
    }

    public int getTcpCount() {
        return tcpCount.get();
    }

    public int getUdpCount() {
        return udpCount.get();
    }
}
