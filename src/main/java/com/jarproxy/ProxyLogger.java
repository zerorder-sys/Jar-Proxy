package com.jarproxy;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public class ProxyLogger {
    public enum Level { TRACE, DEBUG, INFO, WARN, ERROR }

    private static final DateTimeFormatter TIMESTAMP = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    private static volatile Level currentLevel = Level.INFO;
    private static boolean logConnections = true;
    private static boolean logAuthFailures = true;
    private static boolean logDestination = false;

    public static void configure(Config.LoggingConfig config) {
        currentLevel = Level.valueOf(config.level().toUpperCase());
        logConnections = config.log_connections();
        logAuthFailures = config.log_authentication_failures();
        logDestination = config.log_destination();
    }

    private static boolean isEnabled(Level level) {
        return level.ordinal() >= currentLevel.ordinal();
    }

    private static String format(Level level, String message) {
        return String.format("[%s] [%s] %s", LocalDateTime.now().format(TIMESTAMP), level, message);
    }

    public static void info(String message) {
        if (isEnabled(Level.INFO)) System.out.println(format(Level.INFO, message));
    }

    public static void debug(String message) {
        if (isEnabled(Level.DEBUG)) System.out.println(format(Level.DEBUG, message));
    }

    public static void warn(String message) {
        if (isEnabled(Level.WARN)) System.out.println(format(Level.WARN, message));
    }

    public static void error(String message) {
        if (isEnabled(Level.ERROR)) System.err.println(format(Level.ERROR, message));
    }

    public static void trace(String message) {
        if (isEnabled(Level.TRACE)) System.out.println(format(Level.TRACE, message));
    }

    public static void connection(String message) {
        if (logConnections) info(message);
    }

    public static void authFailure(String message) {
        if (logAuthFailures) warn(message);
    }

    public static void destination(String message) {
        if (logDestination) debug(message);
    }
}
