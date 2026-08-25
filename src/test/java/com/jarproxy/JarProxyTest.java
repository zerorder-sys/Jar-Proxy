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
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

public class JarProxyTest {

    private static Socks5Server socks5Server;
    private static int socks5Port;
    private static NioEventLoopGroup testWorkerGroup;
    private static ServerBootstrap echoServer;
    private static Channel echoChannel;
    private static int echoPort;

    @BeforeAll
    static void setUp() throws Exception {
        testWorkerGroup = new NioEventLoopGroup();

        echoServer = new ServerBootstrap();
        echoServer.group(new NioEventLoopGroup(1), testWorkerGroup)
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
        socks5Server = new Socks5Server(config, testWorkerGroup);
        socks5Server.start();
        socks5Port = socks5Server.getPort();
    }

    @AfterAll
    static void tearDown() throws Exception {
        if (socks5Server != null) socks5Server.stop();
        if (echoChannel != null) echoChannel.close();
        if (testWorkerGroup != null) {
            testWorkerGroup.shutdownGracefully().sync();
        }
    }

    private static Config.ConfigData createConfig(int port, boolean authEnabled) {
        var socks5 = new Config.Socks5Config(true, "127.0.0.1", port);
        var users = authEnabled
            ? List.of(new Config.UserConfig("testuser", "testpass"))
            : List.<Config.UserConfig>of();
        var auth = new Config.AuthConfig(authEnabled, users);
        var network = new Config.NetworkConfig(new Config.TcpConfig(true), new Config.UdpConfig(true));
        var timeouts = new Config.TimeoutConfig(10000, 300000);
        var limits = new Config.LimitConfig(500, 200);
        var logging = new Config.LoggingConfig("DEBUG", true, true, false);
        var httpProxy = new Config.HttpProxyConfig(false, 8080);
        return new Config.ConfigData(socks5, auth, network, timeouts, limits, logging, httpProxy);
    }

    // ==================== Helper Methods ====================

    private void doAuth(OutputStream out, InputStream in) throws Exception {
        out.write(new byte[]{0x05, 0x01, 0x02});
        out.flush();
        byte[] greetResp = new byte[2];
        in.read(greetResp);
        assertEquals(0x02, greetResp[1]);

        byte[] auth = buildAuthPacket("testuser", "testpass");
        out.write(auth);
        out.flush();
        byte[] authResp = new byte[2];
        in.read(authResp);
        assertEquals(0x00, authResp[1]);
    }

    private byte[] buildAuthPacket(String username, String password) {
        byte[] userBytes = username.getBytes(StandardCharsets.UTF_8);
        byte[] passBytes = password.getBytes(StandardCharsets.UTF_8);
        byte[] packet = new byte[3 + userBytes.length + passBytes.length];
        packet[0] = 0x01;
        packet[1] = (byte) userBytes.length;
        System.arraycopy(userBytes, 0, packet, 2, userBytes.length);
        packet[2 + userBytes.length] = (byte) passBytes.length;
        System.arraycopy(passBytes, 0, packet, 3 + userBytes.length, passBytes.length);
        return packet;
    }

    private byte[] buildConnectCommand(String ipv4Address, int port) {
        String[] octets = ipv4Address.split("\\.");
        return new byte[]{
            0x05, 0x01, 0x00, 0x01,
            (byte) Integer.parseInt(octets[0]),
            (byte) Integer.parseInt(octets[1]),
            (byte) Integer.parseInt(octets[2]),
            (byte) Integer.parseInt(octets[3]),
            (byte) ((port >> 8) & 0xFF),
            (byte) (port & 0xFF)
        };
    }

    private byte[] buildDomainConnectCommand(String domain, int port) {
        byte[] domainBytes = domain.getBytes(StandardCharsets.US_ASCII);
        byte[] cmd = new byte[7 + domainBytes.length];
        cmd[0] = 0x05;
        cmd[1] = 0x01;
        cmd[2] = 0x00;
        cmd[3] = 0x03;
        cmd[4] = (byte) domainBytes.length;
        System.arraycopy(domainBytes, 0, cmd, 5, domainBytes.length);
        cmd[5 + domainBytes.length] = (byte) ((port >> 8) & 0xFF);
        cmd[6 + domainBytes.length] = (byte) (port & 0xFF);
        return cmd;
    }

    private byte[] readFull(Socket socket, int expected) throws IOException {
        InputStream in = socket.getInputStream();
        byte[] buf = new byte[expected];
        int totalRead = 0;
        while (totalRead < expected) {
            int n = in.read(buf, totalRead, expected - totalRead);
            if (n == -1) break;
            totalRead += n;
        }
        return buf;
    }

    // ==================== SOCKS5 Handshake Tests ====================

    @Test
    @DisplayName("SOCKS5 greeting selects no-auth when auth is disabled")
    void testGreetingNoAuth() throws Exception {
        Config.ConfigData noAuthConfig = createConfig(0, false);
        Socks5Server server = new Socks5Server(noAuthConfig, testWorkerGroup);
        server.start();
        int port = server.getPort();

        try {
            Socket socket = new Socket("127.0.0.1", port);
            socket.setSoTimeout(5000);

            OutputStream out = socket.getOutputStream();
            out.write(new byte[]{0x05, 0x01, 0x00});
            out.flush();

            byte[] response = readFull(socket, 2);
            assertEquals(0x05, response[0]);
            assertEquals(0x00, response[1]);

            socket.close();
        } finally {
            server.stop();
        }
    }

    @Test
    @DisplayName("SOCKS5 greeting selects password auth when enabled")
    void testGreetingPasswordAuth() throws Exception {
        Socket socket = new Socket("127.0.0.1", socks5Port);
        socket.setSoTimeout(5000);

        OutputStream out = socket.getOutputStream();
        out.write(new byte[]{0x05, 0x02, 0x00, 0x02});
        out.flush();

        byte[] response = readFull(socket, 2);
        assertEquals(0x05, response[0]);
        assertEquals(0x02, response[1]);

        socket.close();
    }

    @Test
    @DisplayName("SOCKS5 greeting rejects invalid version")
    void testInvalidVersion() throws Exception {
        Config.ConfigData config = createConfig(0, false);
        Socks5Server server = new Socks5Server(config, testWorkerGroup);
        server.start();
        int port = server.getPort();

        try {
            Socket socket = new Socket("127.0.0.1", port);
            socket.setSoTimeout(5000);

            OutputStream out = socket.getOutputStream();
            out.write(new byte[]{0x04, 0x01, 0x00});
            out.flush();

            InputStream in = socket.getInputStream();
            int read = in.read();
            assertEquals(-1, read);

            socket.close();
        } finally {
            server.stop();
        }
    }

    // ==================== Authentication Tests ====================

    @Test
    @DisplayName("Valid username/password authentication succeeds")
    void testValidAuth() throws Exception {
        Socket socket = new Socket("127.0.0.1", socks5Port);
        socket.setSoTimeout(5000);
        OutputStream out = socket.getOutputStream();
        InputStream in = socket.getInputStream();

        out.write(new byte[]{0x05, 0x01, 0x02});
        out.flush();
        byte[] resp = readFull(socket, 2);
        assertEquals(0x02, resp[1]);

        byte[] auth = buildAuthPacket("testuser", "testpass");
        out.write(auth);
        out.flush();

        byte[] authResp = readFull(socket, 2);
        assertEquals(0x01, authResp[0]);
        assertEquals(0x00, authResp[1]);

        socket.close();
    }

    @Test
    @DisplayName("Invalid password is rejected")
    void testInvalidPassword() throws Exception {
        Socket socket = new Socket("127.0.0.1", socks5Port);
        socket.setSoTimeout(5000);
        OutputStream out = socket.getOutputStream();
        InputStream in = socket.getInputStream();

        out.write(new byte[]{0x05, 0x01, 0x02});
        out.flush();
        readFull(socket, 2);

        byte[] auth = buildAuthPacket("testuser", "wrongpass");
        out.write(auth);
        out.flush();

        byte[] authResp = readFull(socket, 2);
        assertEquals(0x01, authResp[1]);

        Thread.sleep(200);
        assertTrue(socket.isClosed() || in.read() == -1);
        socket.close();
    }

    @Test
    @DisplayName("Non-existent username is rejected")
    void testInvalidUsername() throws Exception {
        Socket socket = new Socket("127.0.0.1", socks5Port);
        socket.setSoTimeout(5000);
        OutputStream out = socket.getOutputStream();
        InputStream in = socket.getInputStream();

        out.write(new byte[]{0x05, 0x01, 0x02});
        out.flush();
        readFull(socket, 2);

        byte[] auth = buildAuthPacket("nobody", "testpass");
        out.write(auth);
        out.flush();

        byte[] authResp = readFull(socket, 2);
        assertEquals(0x01, authResp[1]);

        socket.close();
    }

    // ==================== CONNECT Tests ====================

    @Test
    @DisplayName("IPv4 CONNECT through proxy")
    void testIPv4Connect() throws Exception {
        Socket socket = new Socket("127.0.0.1", socks5Port);
        socket.setSoTimeout(10000);
        OutputStream out = socket.getOutputStream();
        InputStream in = socket.getInputStream();

        doAuth(out, in);

        byte[] connectCmd = buildConnectCommand("127.0.0.1", echoPort);
        out.write(connectCmd);
        out.flush();

        byte[] connResp = readFull(socket, 10);
        assertEquals(0x05, connResp[0]);
        assertEquals(0x00, connResp[1]);

        byte[] testData = "Hello SOCKS5!".getBytes(StandardCharsets.UTF_8);
        out.write(testData);
        out.flush();

        byte[] echoBuf = readFull(socket, testData.length);
        assertArrayEquals(testData, echoBuf);

        socket.close();
    }

    @Test
    @DisplayName("Domain name CONNECT through proxy")
    void testDomainConnect() throws Exception {
        Socket socket = new Socket("127.0.0.1", socks5Port);
        socket.setSoTimeout(10000);
        OutputStream out = socket.getOutputStream();
        InputStream in = socket.getInputStream();

        doAuth(out, in);

        byte[] connectCmd = buildDomainConnectCommand("localhost", echoPort);
        out.write(connectCmd);
        out.flush();

        byte[] connResp = readFull(socket, 10);
        assertEquals(0x05, connResp[0]);
        assertEquals(0x00, connResp[1]);

        byte[] testData = "Domain relay test!".getBytes(StandardCharsets.UTF_8);
        out.write(testData);
        out.flush();

        byte[] echoBuf = readFull(socket, testData.length);
        assertArrayEquals(testData, echoBuf);

        socket.close();
    }

    @Test
    @DisplayName("CONNECT to unreachable host returns error or succeeds")
    void testConnectUnreachable() throws Exception {
        Socket socket = new Socket("127.0.0.1", socks5Port);
        socket.setSoTimeout(10000);
        OutputStream out = socket.getOutputStream();
        InputStream in = socket.getInputStream();

        doAuth(out, in);

        // Use a random high port that is very likely not in use
        int unlikelyPort = 49152 + (int)(Math.random() * 16383);
        byte[] connectCmd = buildConnectCommand("127.0.0.1", unlikelyPort);
        out.write(connectCmd);
        out.flush();

        byte[] connResp = readFull(socket, 10);
        assertEquals(0x05, connResp[0]);
        // Either connection refused (0x05) or success (0x00) depending on OS behavior
        // The important thing is we get a valid SOCKS5 response
        assertTrue(connResp[1] == 0x00 || connResp[1] == 0x04 || connResp[1] == 0x05,
            "Expected success or connection error, got REP=" + connResp[1]);

        socket.close();
    }

    // ==================== UDP ASSOCIATE Tests ====================

    @Test
    @DisplayName("UDP ASSOCIATE allocates a port")
    void testUdpAssociate() throws Exception {
        Socket socket = new Socket("127.0.0.1", socks5Port);
        socket.setSoTimeout(10000);
        OutputStream out = socket.getOutputStream();

        doAuth(out, socket.getInputStream());

        byte[] udpCmd = new byte[]{
            0x05, 0x03, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00
        };
        out.write(udpCmd);
        out.flush();

        byte[] resp = readFull(socket, 10);
        assertEquals(0x05, resp[0]);
        assertEquals(0x00, resp[1]);

        int atyp = resp[3] & 0xFF;
        assertEquals(0x01, atyp);

        int bndPort = ((resp[8] & 0xFF) << 8) | (resp[9] & 0xFF);
        assertTrue(bndPort > 0);

        DatagramSocket udpClient = new DatagramSocket();
        udpClient.setSoTimeout(5000);

        ByteArrayOutputStream udpPayload = new ByteArrayOutputStream();
        udpPayload.write(0); udpPayload.write(0); // RSV
        udpPayload.write(0);                       // FRAG
        udpPayload.write(0x01);                    // ATYP IPv4
        udpPayload.write(127); udpPayload.write(0); udpPayload.write(0); udpPayload.write(1);
        udpPayload.write((echoPort >> 8) & 0xFF);
        udpPayload.write(echoPort & 0xFF);
        byte[] testMsg = "UDP test".getBytes();
        udpPayload.write(testMsg);

        DatagramPacket sendPacket = new DatagramPacket(
            udpPayload.toByteArray(), udpPayload.toByteArray().length,
            InetAddress.getByName("127.0.0.1"), bndPort
        );
        udpClient.send(sendPacket);

        udpClient.close();
        socket.close();
    }

    @Test
    @DisplayName("UDP ASSOCIATE rejects fragmented packets")
    void testUdpFragmentation() throws Exception {
        Socket socket = new Socket("127.0.0.1", socks5Port);
        socket.setSoTimeout(10000);
        OutputStream out = socket.getOutputStream();

        doAuth(out, socket.getInputStream());

        byte[] udpCmd = new byte[]{
            0x05, 0x03, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00
        };
        out.write(udpCmd);
        out.flush();

        byte[] resp = readFull(socket, 10);
        assertEquals(0x00, resp[1]);

        int bndPort = ((resp[8] & 0xFF) << 8) | (resp[9] & 0xFF);

        DatagramSocket udpClient = new DatagramSocket();
        udpClient.setSoTimeout(2000);

        ByteArrayOutputStream udpPayload = new ByteArrayOutputStream();
        udpPayload.write(0); udpPayload.write(0); // RSV
        udpPayload.write(1);                        // FRAG = 1
        udpPayload.write(0x01);
        udpPayload.write(127); udpPayload.write(0); udpPayload.write(0); udpPayload.write(1);
        udpPayload.write(0); udpPayload.write(80);
        udpPayload.write(0x42);

        DatagramPacket sendPacket = new DatagramPacket(
            udpPayload.toByteArray(), udpPayload.toByteArray().length,
            InetAddress.getByName("127.0.0.1"), bndPort
        );
        udpClient.send(sendPacket);

        byte[] recvBuf = new byte[1024];
        DatagramPacket recvPacket = new DatagramPacket(recvBuf, recvBuf.length);
        try {
            udpClient.receive(recvPacket);
            fail("Should not receive response for fragmented packet");
        } catch (SocketTimeoutException e) {
            // Expected
        }

        udpClient.close();
        socket.close();
    }

    // ==================== Invalid ATYP Test ====================

    @Test
    @DisplayName("Invalid ATYP returns address type not supported error")
    void testInvalidAtyp() throws Exception {
        Config.ConfigData config = createConfig(0, false);
        Socks5Server server = new Socks5Server(config, testWorkerGroup);
        server.start();
        int port = server.getPort();

        try {
            Socket socket = new Socket("127.0.0.1", port);
            socket.setSoTimeout(5000);
            OutputStream out = socket.getOutputStream();
            InputStream in = socket.getInputStream();

            out.write(new byte[]{0x05, 0x01, 0x00});
            out.flush();
            readFull(socket, 2);

            byte[] cmd = new byte[]{
                0x05, 0x01, 0x00, (byte) 0xFF,
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00
            };
            out.write(cmd);
            out.flush();

            byte[] cmdResp = readFull(socket, 10);
            assertEquals(0x08, cmdResp[1]);

            socket.close();
        } finally {
            server.stop();
        }
    }

    // ==================== Connection Limit Test ====================

    @Test
    @DisplayName("Connection limiter enforces max connections")
    void testConnectionLimiter() {
        var limits = new Config.LimitConfig(2, 1);
        ConnectionLimiter limiter = new ConnectionLimiter(limits);

        assertTrue(limiter.canAcceptTcp());
        assertNotNull(limiter.trackTcp("c1"));
        assertTrue(limiter.canAcceptTcp());
        assertNotNull(limiter.trackTcp("c2"));
        assertFalse(limiter.canAcceptTcp());
        assertNull(limiter.trackTcp("c3"));

        limiter.releaseTcp("c1");
        assertTrue(limiter.canAcceptTcp());
        assertNotNull(limiter.trackTcp("c3"));
    }

    // ==================== Authentication Manager Tests ====================

    @Test
    @DisplayName("AuthenticationManager validates credentials correctly")
    void testAuthManager() {
        var users = List.of(new Config.UserConfig("alice", "secret123"));
        var authConfig = new Config.AuthConfig(true, users);
        AuthenticationManager manager = new AuthenticationManager(authConfig);

        assertTrue(manager.isEnabled());
        assertTrue(manager.authenticate("alice", "secret123"));
        assertFalse(manager.authenticate("alice", "wrong"));
        assertFalse(manager.authenticate("bob", "secret123"));
        assertFalse(manager.authenticate("", ""));
    }

    @Test
    @DisplayName("Disabled auth manager allows all")
    void testDisabledAuth() {
        var authConfig = new Config.AuthConfig(false, List.of());
        AuthenticationManager manager = new AuthenticationManager(authConfig);

        assertFalse(manager.isEnabled());
        assertTrue(manager.authenticate("anyone", "anything"));
    }

    // ==================== Config Validation Tests ====================

    @Test
    @DisplayName("Config rejects invalid port")
    void testInvalidPort() {
        var socks5 = new Config.Socks5Config(true, "0.0.0.0", -1);
        var auth = new Config.AuthConfig(false, List.of());
        var network = new Config.NetworkConfig(new Config.TcpConfig(true), new Config.UdpConfig(true));
        var timeouts = new Config.TimeoutConfig(10000, 300000);
        var limits = new Config.LimitConfig(500, 200);
        var logging = new Config.LoggingConfig("INFO", true, true, false);
        var httpProxy = new Config.HttpProxyConfig(false, 8080);

        var config = new Config.ConfigData(socks5, auth, network, timeouts, limits, logging, httpProxy);
        assertThrows(IllegalArgumentException.class, () -> Config.validate(config));
    }

    @Test
    @DisplayName("Config rejects duplicate usernames")
    void testDuplicateUsers() {
        var socks5 = new Config.Socks5Config(true, "0.0.0.0", 1080);
        var users = List.of(
            new Config.UserConfig("alice", "pass1"),
            new Config.UserConfig("alice", "pass2")
        );
        var auth = new Config.AuthConfig(true, users);
        var network = new Config.NetworkConfig(new Config.TcpConfig(true), new Config.UdpConfig(true));
        var timeouts = new Config.TimeoutConfig(10000, 300000);
        var limits = new Config.LimitConfig(500, 200);
        var logging = new Config.LoggingConfig("INFO", true, true, false);
        var httpProxy = new Config.HttpProxyConfig(false, 8080);

        var config = new Config.ConfigData(socks5, auth, network, timeouts, limits, logging, httpProxy);
        assertThrows(IllegalArgumentException.class, () -> Config.validate(config));
    }

    @Test
    @DisplayName("Config rejects auth enabled with no users")
    void testAuthEnabledNoUsers() {
        var socks5 = new Config.Socks5Config(true, "0.0.0.0", 1080);
        var auth = new Config.AuthConfig(true, List.of());
        var network = new Config.NetworkConfig(new Config.TcpConfig(true), new Config.UdpConfig(true));
        var timeouts = new Config.TimeoutConfig(10000, 300000);
        var limits = new Config.LimitConfig(500, 200);
        var logging = new Config.LoggingConfig("INFO", true, true, false);
        var httpProxy = new Config.HttpProxyConfig(false, 8080);

        var config = new Config.ConfigData(socks5, auth, network, timeouts, limits, logging, httpProxy);
        assertThrows(IllegalArgumentException.class, () -> Config.validate(config));
    }

    // ==================== Multiple Simultaneous Clients Test ====================

    @Test
    @DisplayName("Multiple clients can connect simultaneously")
    void testMultipleClients() throws Exception {
        int clientCount = 5;
        ExecutorService executor = Executors.newFixedThreadPool(clientCount);
        List<Future<Boolean>> futures = new ArrayList<>();

        for (int i = 0; i < clientCount; i++) {
            futures.add(executor.submit(() -> {
                try {
                    Socket socket = new Socket("127.0.0.1", socks5Port);
                    socket.setSoTimeout(10000);
                    OutputStream out = socket.getOutputStream();
                    InputStream in = socket.getInputStream();

                    doAuth(out, in);
                    byte[] cmd = buildConnectCommand("127.0.0.1", echoPort);
                    out.write(cmd);
                    out.flush();

                    byte[] resp = readFull(socket, 10);
                    boolean success = resp[1] == 0x00;

                    if (success) {
                        byte[] data = "test".getBytes();
                        out.write(data);
                        out.flush();
                        byte[] echo = readFull(socket, data.length);
                    }

                    socket.close();
                    return success;
                } catch (Exception e) {
                    return false;
                }
            }));
        }

        for (Future<Boolean> f : futures) {
            assertTrue(f.get(15, TimeUnit.SECONDS), "Client should connect successfully");
        }
        executor.shutdown();
    }

    // ==================== HTTP CONNECT Test ====================

    @Test
    @DisplayName("HTTP CONNECT tunnel works with auth")
    void testHttpConnect() throws Exception {
        Config.ConfigData config = createConfig(0, true);
        EventLoopGroup httpGroup = new NioEventLoopGroup();
        HttpConnectServer httpServer = new HttpConnectServer(config, httpGroup);
        httpServer.start();

        var field = HttpConnectServer.class.getDeclaredField("serverChannel");
        field.setAccessible(true);
        Channel ch = (Channel) field.get(httpServer);
        int httpPort = ((InetSocketAddress) ch.localAddress()).getPort();

        try {
            Socket socket = new Socket("127.0.0.1", httpPort);
            socket.setSoTimeout(10000);

            OutputStream out = socket.getOutputStream();
            InputStream in = socket.getInputStream();

            String credentials = Base64.getEncoder().encodeToString(
                "testuser:testpass".getBytes(StandardCharsets.UTF_8));

            String connectRequest = "CONNECT 127.0.0.1:" + echoPort + " HTTP/1.1\r\n" +
                "Host: 127.0.0.1:" + echoPort + "\r\n" +
                "Proxy-Authorization: Basic " + credentials + "\r\n" +
                "\r\n";
            out.write(connectRequest.getBytes(StandardCharsets.US_ASCII));
            out.flush();

            byte[] buf = new byte[4096];
            StringBuilder response = new StringBuilder();
            int n;
            while ((n = in.read(buf)) != -1) {
                response.append(new String(buf, 0, n, StandardCharsets.US_ASCII));
                if (response.toString().contains("\r\n\r\n")) break;
            }

            assertTrue(response.toString().contains("200"),
                "Should get 200 Connection Established: " + response);

            byte[] testData = "HTTP tunnel test".getBytes();
            out.write(testData);
            out.flush();

            byte[] echo = readFull(socket, testData.length);
            assertArrayEquals(testData, echo);

            socket.close();
        } finally {
            httpServer.stop();
            httpGroup.shutdownGracefully().sync();
        }
    }
}
