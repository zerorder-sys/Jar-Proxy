# JarProxy - Java 21 SOCKS5 Proxy Server

A production-quality, RFC-compliant SOCKS5 proxy server built with Java 21 and Netty 4. Designed for deployment on a Pterodactyl Java container as a private proxy.

## Features

- **RFC 1928 SOCKS5** - Full protocol support (CONNECT, UDP ASSOCIATE)
- **RFC 1929 Authentication** - Username/password auth with multiple users
- **IPv4/IPv6/Domain** - All SOCKS5 address types
- **UDP ASSOCIATE** - Standards-compliant UDP relay with SOCKS5 packet format
- **HTTP CONNECT** - Optional HTTP/HTTPS tunnel proxy (disabled by default)
- **Configurable** - Full YAML configuration
- **Secure** - Connection limits, timeouts, input validation, no password logging
- **Pterodactyl Ready** - Single JAR, no root/systemd/Docker required

## Architecture

```
JarProxy/
├── Main.java                 - Entry point, startup, shutdown hook
├── Config.java               - YAML configuration loader & validator
├── ProxyLogger.java          - Timestamped console logging
├── AuthenticationManager.java - User credential management
├── ConnectionLimiter.java    - TCP/UDP connection limits
├── Socks5Server.java         - Netty SOCKS5 TCP listener
├── Socks5ClientHandler.java  - SOCKS5 protocol state machine
├── TcpRelay.java             - Bidirectional TCP data relay
├── UdpAssociate.java         - SOCKS5 UDP ASSOCIATE relay
└── HttpConnectServer.java    - HTTP CONNECT tunnel proxy
```

## Build

### Prerequisites

- **Java 21** (JDK)
- **Apache Maven 3.9+**

### Compile

```bash
cd JarProxy
mvn clean package -DskipTests
```

### Result

```
target/JarProxy.jar
```

### Build with tests

```bash
mvn clean package
```

## Configuration

The first run creates `config.yml` automatically. Edit it before starting:

```yaml
server:
  host: "0.0.0.0"
  port: 1080

authentication:
  enabled: true
  users:
    - username: "proxyuser"
      password: "CHANGE_THIS_PASSWORD"

network:
  tcp:
    enabled: true
  udp:
    enabled: true

timeouts:
  connection: 10000
  idle: 300000

limits:
  max_connections: 500
  max_udp_associations: 200

logging:
  level: "INFO"
  log_connections: true
  log_authentication_failures: true
  log_destination: false

http_proxy:
  enabled: false
  port: 8080
```

### Configuration Options

| Option | Description |
|--------|-------------|
| `server.host` | Bind address (use `0.0.0.0` for Pterodactyl) |
| `server.port` | SOCKS5 listening port |
| `authentication.enabled` | Enable/disable username/password auth |
| `authentication.users` | List of username/password pairs |
| `network.tcp.enabled` | Enable TCP CONNECT support |
| `network.udp.enabled` | Enable UDP ASSOCIATE support |
| `timeouts.connection` | TCP connect timeout (ms) |
| `timeouts.idle` | Idle connection timeout (ms) |
| `limits.max_connections` | Maximum simultaneous TCP connections |
| `limits.max_udp_associations` | Maximum simultaneous UDP associations |
| `logging.level` | TRACE, DEBUG, INFO, WARN, ERROR |
| `logging.log_connections` | Log connect/disconnect events |
| `logging.log_authentication_failures` | Log failed auth attempts |
| `logging.log_destination` | Log proxy destinations (privacy risk) |
| `http_proxy.enabled` | Enable HTTP CONNECT proxy |
| `http_proxy.port` | HTTP CONNECT listening port |

## Deployment to Pterodactyl

### 1. Create the Server

1. In Pterodactyl Panel, create a new **Java** server
2. Select **Java 21** (or latest available)
3. Set the startup command to:
   ```
   java -jar JarProxy.jar
   ```
4. Note the **allocation port** assigned by Pterodactyl

### 2. Upload the JAR

Upload `target/JarProxy.jar` to your server's `/home/container/` directory via:
- Pterodactyl File Manager
- SFTP (use your Pterodactyl credentials)

### 3. Configure the Port

Edit `config.yml` to use the Pterodactyl allocation port:

```yaml
server:
  host: "0.0.0.0"
  port: 25565   # Use your Pterodactyl allocation port
```

### 4. Configure Credentials

Change the default password immediately:

```yaml
authentication:
  enabled: true
  users:
    - username: "myuser"
      password: "YOUR_SECURE_PASSWORD_HERE"
```

### 5. Start the Server

Click **Start** in the Pterodactyl Panel, or:

```bash
java -jar JarProxy.jar
```

### 6. Firewall

On your VPS, ensure the port is open:

```bash
# UFW
sudo ufw allow 25565/tcp

# iptables
sudo iptables -A INPUT -p tcp --dport 25565 -j ACCEPT
```

For UDP support (SOCKS5 UDP ASSOCIATE), also allow UDP:

```bash
sudo ufw allow 25565/udp
```

## Connecting with ProxyBridge

### ProxyBridge Configuration

```
Proxy type: SOCKS5
Host: YOUR_VPS_IP
Port: 1080
Username: proxyuser
Password: YOUR_PASSWORD
```

### Windows System Proxy

1. Open **Settings** > **Network & Internet** > **Proxy**
2. Enable **Use a proxy server**
3. Set address: `YOUR_VPS_IP`
4. Set port: `1080`
5. Check **Don't use proxy for local addresses**

### Browser Configuration (Firefox)

1. Open Firefox > Settings > Network Settings
2. Select **Manual proxy configuration**
3. SOCKS Host: `YOUR_VPS_IP`
4. Port: `1080`
5. Select **SOCKS v5**
6. Check **Proxy DNS when using SOCKS v5**

## Testing

### Test TCP Connection

```bash
# Using curl through the proxy
curl -x socks5://proxyuser:password@YOUR_VPS_IP:1080 http://httpbin.org/ip

# Using netcat through the proxy (if you have a SOCKS-capable netcat)
```

### Test UDP Association

Use a SOCKS5-capable UDP client. The proxy will:
1. Return a UDP bind port on TCP control connection
2. Accept SOCKS5 UDP packets on that port
3. Relay data to/from the target

### Test HTTP CONNECT

```bash
curl -x http://proxyuser:password@YOUR_VPS_IP:8080 http://httpbin.org/ip
```

### Run Unit Tests

```bash
mvn test
```

## Important Notes

### SOCKS5 UDP and Gaming

This proxy implements standards-compliant SOCKS5 UDP ASSOCIATE. However:

- Some applications use non-standard networking that may be incompatible
- UDP relay adds latency
- Not all games will work through a SOCKS5 UDP relay
- This is a general-purpose proxy, not a game-specific tool

### Security Recommendations

1. **Change the default password** immediately
2. **Use strong passwords** (16+ characters)
3. **Enable authentication** (don't run as open proxy)
4. **Restrict connections** to your IP if possible
5. **Monitor logs** for unauthorized access attempts
6. **Keep Java updated** to the latest version
7. **Use firewall rules** to limit access

### Troubleshooting

**Server won't start:**
- Check Java version: `java -version`
- Check port availability: `netstat -tlnp | grep 1080`
- Check config.yml syntax

**Can't connect:**
- Verify the port is open in your firewall
- Check the server is listening: `netstat -tlnp | grep <port>`
- Verify credentials match config.yml
- Check server logs for errors

**UDP not working:**
- Ensure UDP is enabled in config.yml
- Ensure UDP port is open in firewall
- Some NAT configurations may interfere

**Pterodactyl issues:**
- Ensure the allocation port matches config.yml
- Check the server console for startup errors
- Verify `java -jar JarProxy.jar` works in the container

## License

Private use. Not for distribution as a public proxy service.
