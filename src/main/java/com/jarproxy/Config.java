package com.jarproxy;

import org.yaml.snakeyaml.Yaml;
import java.io.*;
import java.nio.file.*;
import java.util.*;

public class Config {
    public record Socks5Config(boolean enabled, String host, int port) {}
    public record UserConfig(String username, String password) {}
    public record AuthConfig(boolean enabled, List<UserConfig> users) {}
    public record TcpConfig(boolean enabled) {}
    public record UdpConfig(boolean enabled) {}
    public record NetworkConfig(TcpConfig tcp, UdpConfig udp) {}
    public record TimeoutConfig(int connection, int idle) {}
    public record LimitConfig(int max_connections, int max_udp_associations) {}
    public record LoggingConfig(String level, boolean log_connections, boolean log_authentication_failures, boolean log_destination) {}
    public record HttpProxyConfig(boolean enabled, int port) {}

    public record ConfigData(
        Socks5Config socks5,
        AuthConfig authentication,
        NetworkConfig network,
        TimeoutConfig timeouts,
        LimitConfig limits,
        LoggingConfig logging,
        HttpProxyConfig http_proxy
    ) {}

    private static final String DEFAULT_CONFIG = """
        socks5:
          enabled: true
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
        """;

    public static ConfigData load(String path) throws IOException {
        Path configPath = Path.of(path);
        if (!Files.exists(configPath)) {
            System.out.println("[INFO] No config.yml found. Creating default config...");
            Files.writeString(configPath, DEFAULT_CONFIG);
            System.out.println("[INFO] Default config.yml created. Please edit it before running.");
            System.exit(0);
        }

        Yaml yaml = new Yaml();
        Map<String, Object> raw;
        try (FileInputStream fis = new FileInputStream(configPath.toFile())) {
            raw = yaml.load(fis);
        }

        if (raw == null) {
            throw new IOException("Empty or invalid config.yml");
        }

        return parseConfig(raw);
    }

    @SuppressWarnings("unchecked")
    private static ConfigData parseConfig(Map<String, Object> raw) {
        Map<String, Object> socks5Map = requireMap(raw, "socks5");
        Map<String, Object> authMap = requireMap(raw, "authentication");
        Map<String, Object> netMap = requireMap(raw, "network");
        Map<String, Object> timeoutMap = requireMap(raw, "timeouts");
        Map<String, Object> limitMap = requireMap(raw, "limits");
        Map<String, Object> logMap = requireMap(raw, "logging");
        Map<String, Object> httpMap = requireMap(raw, "http_proxy");

        Socks5Config socks5 = new Socks5Config(
            (boolean) socks5Map.get("enabled"),
            String.valueOf(socks5Map.get("host")),
            ((Number) socks5Map.get("port")).intValue()
        );

        boolean authEnabled = (boolean) authMap.get("enabled");
        List<UserConfig> users = new ArrayList<>();
        List<Map<String, String>> userList = (List<Map<String, String>>) authMap.get("users");
        if (userList != null) {
            for (Map<String, String> u : userList) {
                users.add(new UserConfig(u.get("username"), u.get("password")));
            }
        }
        AuthConfig auth = new AuthConfig(authEnabled, users);

        Map<String, Object> tcpMap = requireMap(netMap, "tcp");
        Map<String, Object> udpMap = requireMap(netMap, "udp");
        NetworkConfig network = new NetworkConfig(
            new TcpConfig((boolean) tcpMap.get("enabled")),
            new UdpConfig((boolean) udpMap.get("enabled"))
        );

        TimeoutConfig timeouts = new TimeoutConfig(
            ((Number) timeoutMap.get("connection")).intValue(),
            ((Number) timeoutMap.get("idle")).intValue()
        );

        LimitConfig limits = new LimitConfig(
            ((Number) limitMap.get("max_connections")).intValue(),
            ((Number) limitMap.get("max_udp_associations")).intValue()
        );

        LoggingConfig logging = new LoggingConfig(
            String.valueOf(logMap.get("level")),
            (boolean) logMap.get("log_connections"),
            (boolean) logMap.get("log_authentication_failures"),
            (boolean) logMap.get("log_destination")
        );

        HttpProxyConfig httpProxy = new HttpProxyConfig(
            (boolean) httpMap.get("enabled"),
            ((Number) httpMap.get("port")).intValue()
        );

        ConfigData config = new ConfigData(socks5, auth, network, timeouts, limits, logging, httpProxy);
        validate(config);
        return config;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> requireMap(Map<String, Object> parent, String key) {
        Object value = parent.get(key);
        if (value == null) {
            throw new IllegalArgumentException("Missing required config section: " + key);
        }
        if (!(value instanceof Map)) {
            throw new IllegalArgumentException("Config section '" + key + "' must be a map, got: " + value.getClass().getSimpleName());
        }
        return (Map<String, Object>) value;
    }

    public static void validate(ConfigData config) {
        List<String> errors = new ArrayList<>();

        if (config.socks5.enabled() && (config.socks5.port() < 1 || config.socks5.port() > 65535)) {
            errors.add("socks5.port must be between 1 and 65535");
        }
        if (config.http_proxy.enabled() && (config.http_proxy.port() < 1 || config.http_proxy.port() > 65535)) {
            errors.add("http_proxy.port must be between 1 and 65535");
        }
        if (config.socks5.enabled() && config.http_proxy.enabled()
            && config.socks5.port() == config.http_proxy.port() && config.socks5.port() != 0) {
            errors.add("SOCKS5 and HTTP proxy ports must be different");
        }
        if (config.authentication.enabled() && config.authentication.users().isEmpty()) {
            errors.add("Authentication is enabled but no users are configured");
        }
        if (config.authentication.enabled()) {
            Set<String> usernames = new HashSet<>();
            for (var user : config.authentication.users()) {
                if (user.username() == null || user.username().isBlank()) {
                    errors.add("Username cannot be empty");
                }
                if (user.password() == null || user.password().isBlank()) {
                    errors.add("Password cannot be empty for user: " + user.username());
                }
                if (!usernames.add(user.username())) {
                    errors.add("Duplicate username: " + user.username());
                }
            }
        }
        if (config.timeouts.connection() < 1000) {
            errors.add("timeouts.connection must be at least 1000ms");
        }
        if (config.timeouts.idle() < 1000) {
            errors.add("timeouts.idle must be at least 1000ms");
        }
        if (config.limits.max_connections() < 1) {
            errors.add("limits.max_connections must be at least 1");
        }
        if (config.limits.max_udp_associations() < 1) {
            errors.add("limits.max_udp_associations must be at least 1");
        }

        String[] validLevels = {"TRACE", "DEBUG", "INFO", "WARN", "ERROR"};
        if (!Arrays.asList(validLevels).contains(config.logging.level().toUpperCase())) {
            errors.add("logging.level must be one of: TRACE, DEBUG, INFO, WARN, ERROR");
        }

        if (!errors.isEmpty()) {
            StringBuilder sb = new StringBuilder("Configuration errors:\n");
            for (String error : errors) {
                sb.append("  - ").append(error).append("\n");
            }
            throw new IllegalArgumentException(sb.toString());
        }
    }
}
