package com.jarproxy;

import io.netty.bootstrap.ServerBootstrap;
import io.netty.buffer.*;
import io.netty.channel.*;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import org.junit.jupiter.api.*;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Full integration test: starts SOCKS5 server, connects via raw socket,
 * performs handshake + auth + CONNECT + data relay.
 */
public class IntegrationTest {

    private static EventLoopGroup workerGroup;
    private static Socks5Server socks5Server;
    private static int socks5Port;
    private static ServerBootstrap echoServer;
    private static Channel echoChannel;
    private static int echoPort;

    @BeforeAll
    static void setUp() throws Exception {
        workerGroup = new NioEventLoopGroup();

        echoServer = new ServerBootstrap();
        echoServer.group(new NioEventLoopGroup(1), workerGroup)
            .channel(NioServerSocketChannel.class)
            .childHandler(new ChannelInitializer<SocketChannel>() {
                @Override
                protected void initChannel(SocketChannel ch) {
                    ch.pipeline().addLast(new SimpleChannelInboundHandler<ByteBuf>() {
                        @Override
                        protected void channelRead0(ChannelHandlerContext ctx, ByteBuf msg) {
                            ctx.writeAndFlush(msg.retain());
                        }
                    });
                }
            });
        ChannelFuture echoFuture = echoServer.bind(0).sync();
        echoChannel = echoFuture.channel();
        echoPort = ((InetSocketAddress) echoChannel.localAddress()).getPort();

        Config.ConfigData config = createConfig(0, true);
        socks5Server = new Socks5Server(config, workerGroup);
        socks5Server.start();
        socks5Port = socks5Server.getPort();
    }

    @AfterAll
    static void tearDown() throws Exception {
        if (socks5Server != null) socks5Server.stop();
        if (echoChannel != null) echoChannel.close();
        if (workerGroup != null) workerGroup.shutdownGracefully().sync();
    }

    private static Config.ConfigData createConfig(int port, boolean auth) {
        var socks5 = new Config.Socks5Config(true, "127.0.0.1", port);
        var users = auth ? List.of(new Config.UserConfig("testuser", "testpass")) : List.<Config.UserConfig>of();
        var authCfg = new Config.AuthConfig(auth, users);
        var network = new Config.NetworkConfig(new Config.TcpConfig(true), new Config.UdpConfig(true));
        var timeouts = new Config.TimeoutConfig(10000, 300000);
        var limits = new Config.LimitConfig(500, 200);
        var logging = new Config.LoggingConfig("DEBUG", true, true, true);
        var httpProxy = new Config.HttpProxyConfig(false, 8080);
        return new Config.ConfigData(socks5, authCfg, network, timeouts, limits, logging, httpProxy);
    }

    @Test
    @DisplayName("Full SOCKS5 flow: greeting -> auth -> IPv4 CONNECT -> data relay")
    void testFullSocks5Flow() throws Exception {
        Socket socket = new Socket("127.0.0.1", socks5Port);
        socket.setSoTimeout(10000);
        OutputStream out = socket.getOutputStream();
        InputStream in = socket.getInputStream();

        // Step 1: Send greeting (no-auth + password-auth)
        out.write(new byte[]{0x05, 0x02, 0x00, 0x02});
        out.flush();

        // Step 2: Read method selection
        byte[] greetResp = readExact(in, 2);
        assertEquals(0x05, greetResp[0], "Version should be 5");
        assertEquals(0x02, greetResp[1], "Should select password auth");

        // Step 3: Send username/password
        byte[] authPacket = buildAuth("testuser", "testpass");
        out.write(authPacket);
        out.flush();

        // Step 4: Read auth response
        byte[] authResp = readExact(in, 2);
        assertEquals(0x00, authResp[1], "Auth should succeed");

        // Step 5: Send CONNECT to echo server
        byte[] connectCmd = buildConnect("127.0.0.1", echoPort);
        out.write(connectCmd);
        out.flush();

        // Step 6: Read CONNECT response
        byte[] connResp = readExact(in, 10);
        assertEquals(0x05, connResp[0], "Version should be 5");
        assertEquals(0x00, connResp[1], "CONNECT should succeed");

        // Step 7: Send data through tunnel
        byte[] testData = "Hello from integration test!".getBytes(StandardCharsets.UTF_8);
        out.write(testData);
        out.flush();

        // Step 8: Read echoed data
        byte[] echoed = readExact(in, testData.length);
        assertArrayEquals(testData, echoed, "Echoed data should match");

        socket.close();
    }

    @Test
    @DisplayName("Auth failure closes connection")
    void testAuthFailure() throws Exception {
        Socket socket = new Socket("127.0.0.1", socks5Port);
        socket.setSoTimeout(5000);
        OutputStream out = socket.getOutputStream();
        InputStream in = socket.getInputStream();

        out.write(new byte[]{0x05, 0x01, 0x02});
        out.flush();
        readExact(in, 2);

        byte[] authPacket = buildAuth("testuser", "wrongpassword");
        out.write(authPacket);
        out.flush();

        byte[] authResp = readExact(in, 2);
        assertEquals(0x01, authResp[1], "Auth should fail");

        // Server should close connection
        Thread.sleep(200);
        int read = in.read();
        assertEquals(-1, read, "Connection should be closed");
        socket.close();
    }

    @Test
    @DisplayName("Multiple sequential requests on one connection")
    void testMultipleRequests() throws Exception {
        Socket socket = new Socket("127.0.0.1", socks5Port);
        socket.setSoTimeout(10000);
        OutputStream out = socket.getOutputStream();
        InputStream in = socket.getInputStream();

        // Auth
        out.write(new byte[]{0x05, 0x01, 0x02});
        out.flush();
        readExact(in, 2);
        out.write(buildAuth("testuser", "testpass"));
        out.flush();
        readExact(in, 2);

        // First CONNECT
        out.write(buildConnect("127.0.0.1", echoPort));
        out.flush();
        byte[] resp1 = readExact(in, 10);
        assertEquals(0x00, resp1[1]);

        byte[] data1 = "first".getBytes();
        out.write(data1);
        out.flush();
        assertArrayEquals(data1, readExact(in, data1.length));

        socket.close();
    }

    @Test
    @DisplayName("Domain name CONNECT")
    void testDomainConnect() throws Exception {
        Socket socket = new Socket("127.0.0.1", socks5Port);
        socket.setSoTimeout(10000);
        OutputStream out = socket.getOutputStream();
        InputStream in = socket.getInputStream();

        out.write(new byte[]{0x05, 0x01, 0x02});
        out.flush();
        readExact(in, 2);
        out.write(buildAuth("testuser", "testpass"));
        out.flush();
        readExact(in, 2);

        // Domain CONNECT
        byte[] domainCmd = buildDomainConnect("localhost", echoPort);
        out.write(domainCmd);
        out.flush();

        byte[] resp = readExact(in, 10);
        assertEquals(0x00, resp[1], "Domain CONNECT should succeed");

        byte[] data = "domain test".getBytes();
        out.write(data);
        out.flush();
        assertArrayEquals(data, readExact(in, data.length));

        socket.close();
    }

    @Test
    @DisplayName("Concurrent clients all succeed")
    void testConcurrentClients() throws Exception {
        int count = 10;
        ExecutorService exec = Executors.newFixedThreadPool(count);
        List<Future<Boolean>> futures = new ArrayList<>();

        for (int i = 0; i < count; i++) {
            final int idx = i;
            futures.add(exec.submit(() -> {
                try {
                    Socket s = new Socket("127.0.0.1", socks5Port);
                    s.setSoTimeout(10000);
                    OutputStream out = s.getOutputStream();
                    InputStream in = s.getInputStream();

                    out.write(new byte[]{0x05, 0x01, 0x02});
                    out.flush();
                    readExact(in, 2);
                    out.write(buildAuth("testuser", "testpass"));
                    out.flush();
                    readExact(in, 2);

                    out.write(buildConnect("127.0.0.1", echoPort));
                    out.flush();
                    byte[] resp = readExact(in, 10);
                    if (resp[1] != 0x00) { s.close(); return false; }

                    byte[] data = ("client-" + idx).getBytes();
                    out.write(data);
                    out.flush();
                    byte[] echo = readExact(in, data.length);
                    boolean ok = Arrays.equals(data, echo);
                    s.close();
                    return ok;
                } catch (Exception e) {
                    return false;
                }
            }));
        }

        for (Future<Boolean> f : futures) {
            assertTrue(f.get(15, TimeUnit.SECONDS), "Client should work");
        }
        exec.shutdown();
    }

    @Test
    @DisplayName("Curl simulation: greeting+auth in single TCP write, then CONNECT")
    void testCurlSimulatedGreetingPlusAuth() throws Exception {
        Socket socket = new Socket("127.0.0.1", socks5Port);
        socket.setSoTimeout(10000);
        OutputStream out = socket.getOutputStream();
        InputStream in = socket.getInputStream();

        byte[] greeting = new byte[]{0x05, 0x02, 0x00, 0x02};
        byte[] auth = buildAuth("testuser", "testpass");
        byte[] combined = new byte[greeting.length + auth.length];
        System.arraycopy(greeting, 0, combined, 0, greeting.length);
        System.arraycopy(auth, 0, combined, greeting.length, auth.length);
        out.write(combined);
        out.flush();

        byte[] greetResp = readExact(in, 2);
        assertEquals(0x05, greetResp[0]);
        assertEquals(0x02, greetResp[1]);

        byte[] authResp = readExact(in, 2);
        assertEquals(0x00, authResp[1], "Auth should succeed");

        out.write(buildConnect("127.0.0.1", echoPort));
        out.flush();

        byte[] connResp = readExact(in, 10);
        assertEquals(0x00, connResp[1]);

        byte[] data = "curl simulation test".getBytes();
        out.write(data);
        out.flush();
        assertArrayEquals(data, readExact(in, data.length));

        socket.close();
    }

    @Test
    @DisplayName("Target connection refused returns proper error")
    void testTargetConnectionRefused() throws Exception {
        Socket socket = new Socket("127.0.0.1", socks5Port);
        socket.setSoTimeout(10000);
        OutputStream out = socket.getOutputStream();
        InputStream in = socket.getInputStream();

        out.write(new byte[]{0x05, 0x01, 0x02});
        out.flush();
        readExact(in, 2);
        out.write(buildAuth("testuser", "testpass"));
        out.flush();
        readExact(in, 2);

        out.write(buildConnect("127.0.0.1", 1));
        out.flush();

        byte[] resp = readExact(in, 10);
        assertEquals(0x05, resp[0]);
        assertNotEquals(0x00, resp[1], "Should return error for refused connection");

        socket.close();
    }

    @Test
    @DisplayName("Idle timeout closes stale connections")
    void testIdleTimeout() throws Exception {
        Config.ConfigData config = createConfig(socks5Port + 100, true);
        Socks5Server shortTimeoutServer = new Socks5Server(config, workerGroup);
        shortTimeoutServer.start();
        int port = shortTimeoutServer.getPort();

        Socket socket = new Socket("127.0.0.1", port);
        socket.setSoTimeout(10000);
        OutputStream out = socket.getOutputStream();
        InputStream in = socket.getInputStream();

        out.write(new byte[]{0x05, 0x01, 0x02});
        out.flush();
        readExact(in, 2);

        out.write(buildAuth("testuser", "testpass"));
        out.flush();
        readExact(in, 2);

        Thread.sleep(200);
        socket.close();
        shortTimeoutServer.stop();
    }

    // ==================== HTTP Proxy Tests ====================

    @Test
    @DisplayName("HTTP CONNECT tunnel with auth")
    void testHttpConnectWithAuth() throws Exception {
        Config.ConfigData config = createConfigWithHttp(0, 0, true);
        HttpConnectServer httpServer = new HttpConnectServer(config, workerGroup);
        httpServer.start();
        int httpPort = httpServer.getServerPort();

        Socket socket = new Socket("127.0.0.1", httpPort);
        socket.setSoTimeout(10000);
        OutputStream out = socket.getOutputStream();
        InputStream in = socket.getInputStream();

        String auth = Base64.getEncoder().encodeToString("testuser:testpass".getBytes());
        String request = "CONNECT 127.0.0.1:" + echoPort + " HTTP/1.1\r\n" +
            "Host: 127.0.0.1:" + echoPort + "\r\n" +
            "Proxy-Authorization: Basic " + auth + "\r\n" +
            "\r\n";
        out.write(request.getBytes(StandardCharsets.US_ASCII));
        out.flush();

        String response = readHttpResponse(in);
        assertTrue(response.contains("200"), "CONNECT should succeed, got: " + response);

        byte[] data = "http connect test".getBytes(StandardCharsets.UTF_8);
        out.write(data);
        out.flush();
        assertArrayEquals(data, readExact(in, data.length));

        socket.close();
        httpServer.stop();
    }

    @Test
    @DisplayName("HTTP CONNECT without auth when auth enabled fails")
    void testHttpConnectNoAuth() throws Exception {
        Config.ConfigData config = createConfigWithHttp(0, 0, true);
        HttpConnectServer httpServer = new HttpConnectServer(config, workerGroup);
        httpServer.start();
        int httpPort = httpServer.getServerPort();

        Socket socket = new Socket("127.0.0.1", httpPort);
        socket.setSoTimeout(5000);
        OutputStream out = socket.getOutputStream();
        InputStream in = socket.getInputStream();

        String request = "CONNECT 127.0.0.1:" + echoPort + " HTTP/1.1\r\n" +
            "Host: 127.0.0.1:" + echoPort + "\r\n" +
            "\r\n";
        out.write(request.getBytes(StandardCharsets.US_ASCII));
        out.flush();

        String response = readHttpResponse(in);
        assertTrue(response.contains("407"), "Should get 407, got: " + response);

        socket.close();
        httpServer.stop();
    }

    @Test
    @DisplayName("HTTP CONNECT without auth when auth disabled succeeds")
    void testHttpConnectNoAuthDisabled() throws Exception {
        Config.ConfigData config = createConfigWithHttp(0, 0, false);
        HttpConnectServer httpServer = new HttpConnectServer(config, workerGroup);
        httpServer.start();
        int httpPort = httpServer.getServerPort();

        Socket socket = new Socket("127.0.0.1", httpPort);
        socket.setSoTimeout(10000);
        OutputStream out = socket.getOutputStream();
        InputStream in = socket.getInputStream();

        String request = "CONNECT 127.0.0.1:" + echoPort + " HTTP/1.1\r\n" +
            "Host: 127.0.0.1:" + echoPort + "\r\n" +
            "\r\n";
        out.write(request.getBytes(StandardCharsets.US_ASCII));
        out.flush();

        String response = readHttpResponse(in);
        assertTrue(response.contains("200"), "CONNECT should succeed, got: " + response);

        byte[] data = "no auth http test".getBytes(StandardCharsets.UTF_8);
        out.write(data);
        out.flush();
        assertArrayEquals(data, readExact(in, data.length));

        socket.close();
        httpServer.stop();
    }

    @Test
    @DisplayName("HTTP CONNECT data relay with combined header+data in single write")
    void testHttpConnectCombinedWrite() throws Exception {
        Config.ConfigData config = createConfigWithHttp(0, 0, false);
        HttpConnectServer httpServer = new HttpConnectServer(config, workerGroup);
        httpServer.start();
        int httpPort = httpServer.getServerPort();

        Socket socket = new Socket("127.0.0.1", httpPort);
        socket.setSoTimeout(10000);
        OutputStream out = socket.getOutputStream();
        InputStream in = socket.getInputStream();

        String request = "CONNECT 127.0.0.1:" + echoPort + " HTTP/1.1\r\n" +
            "Host: 127.0.0.1:" + echoPort + "\r\n" +
            "\r\n";
        byte[] data = "combined write test".getBytes(StandardCharsets.UTF_8);
        byte[] combined = new byte[request.getBytes(StandardCharsets.US_ASCII).length + data.length];
        System.arraycopy(request.getBytes(StandardCharsets.US_ASCII), 0, combined, 0, request.getBytes(StandardCharsets.US_ASCII).length);
        System.arraycopy(data, 0, combined, request.getBytes(StandardCharsets.US_ASCII).length, data.length);
        out.write(combined);
        out.flush();

        String response = readHttpResponse(in);
        assertTrue(response.contains("200"), "CONNECT should succeed, got: " + response);
        assertArrayEquals(data, readExact(in, data.length));

        socket.close();
        httpServer.stop();
    }

    @Test
    @DisplayName("HTTP target connection refused returns 502")
    void testHttpConnectTargetRefused() throws Exception {
        Config.ConfigData config = createConfigWithHttp(0, 0, false);
        HttpConnectServer httpServer = new HttpConnectServer(config, workerGroup);
        httpServer.start();
        int httpPort = httpServer.getServerPort();

        Socket socket = new Socket("127.0.0.1", httpPort);
        socket.setSoTimeout(10000);
        OutputStream out = socket.getOutputStream();
        InputStream in = socket.getInputStream();

        String request = "CONNECT 127.0.0.1:1 HTTP/1.1\r\nHost: 127.0.0.1:1\r\n\r\n";
        out.write(request.getBytes(StandardCharsets.US_ASCII));
        out.flush();

        String response = readHttpResponse(in);
        assertTrue(response.contains("502"), "Should get 502, got: " + response);

        socket.close();
        httpServer.stop();
    }

    private static Config.ConfigData createConfigWithHttp(int socksPort, int httpPort, boolean auth) {
        var socks5 = new Config.Socks5Config(false, "127.0.0.1", socksPort);
        var users = auth ? List.of(new Config.UserConfig("testuser", "testpass")) : List.<Config.UserConfig>of();
        var authCfg = new Config.AuthConfig(auth, users);
        var network = new Config.NetworkConfig(new Config.TcpConfig(true), new Config.UdpConfig(true));
        var timeouts = new Config.TimeoutConfig(10000, 300000);
        var limits = new Config.LimitConfig(500, 200);
        var logging = new Config.LoggingConfig("DEBUG", true, true, true);
        var httpProxy = new Config.HttpProxyConfig(true, httpPort);
        return new Config.ConfigData(socks5, authCfg, network, timeouts, limits, logging, httpProxy);
    }

    private static String readHttpResponse(InputStream in) throws IOException {
        StringBuilder sb = new StringBuilder();
        int prev = 0, cur;
        while ((cur = in.read()) != -1) {
            sb.append((char) cur);
            if (prev == '\r' && cur == '\n' && sb.length() >= 4) {
                String s = sb.toString();
                if (s.endsWith("\r\n\r\n")) break;
            }
            prev = cur;
        }
        return sb.toString();
    }

    // ==================== Helpers ====================

    private static byte[] readExact(InputStream in, int n) throws IOException {
        byte[] buf = new byte[n];
        int total = 0;
        while (total < n) {
            int read = in.read(buf, total, n - total);
            if (read == -1) throw new IOException("EOF at " + total + "/" + n);
            total += read;
        }
        return buf;
    }

    private static byte[] buildAuth(String user, String pass) {
        byte[] u = user.getBytes(StandardCharsets.UTF_8);
        byte[] p = pass.getBytes(StandardCharsets.UTF_8);
        byte[] pkt = new byte[3 + u.length + p.length];
        pkt[0] = 0x01;
        pkt[1] = (byte) u.length;
        System.arraycopy(u, 0, pkt, 2, u.length);
        pkt[2 + u.length] = (byte) p.length;
        System.arraycopy(p, 0, pkt, 3 + u.length, p.length);
        return pkt;
    }

    private static byte[] buildConnect(String ipv4, int port) {
        String[] o = ipv4.split("\\.");
        return new byte[]{0x05, 0x01, 0x00, 0x01,
            (byte) Integer.parseInt(o[0]), (byte) Integer.parseInt(o[1]),
            (byte) Integer.parseInt(o[2]), (byte) Integer.parseInt(o[3]),
            (byte) ((port >> 8) & 0xFF), (byte) (port & 0xFF)};
    }

    private static byte[] buildDomainConnect(String domain, int port) {
        byte[] d = domain.getBytes(StandardCharsets.US_ASCII);
        byte[] cmd = new byte[7 + d.length];
        cmd[0] = 0x05; cmd[1] = 0x01; cmd[2] = 0x00; cmd[3] = 0x03;
        cmd[4] = (byte) d.length;
        System.arraycopy(d, 0, cmd, 5, d.length);
        cmd[5 + d.length] = (byte) ((port >> 8) & 0xFF);
        cmd[6 + d.length] = (byte) (port & 0xFF);
        return cmd;
    }
}
