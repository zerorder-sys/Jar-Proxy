package com.jarproxy;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class AuthenticationManager {
    private final boolean enabled;
    private final Map<String, byte[]> users = new ConcurrentHashMap<>();

    public AuthenticationManager(Config.AuthConfig config) {
        this.enabled = config.enabled();
        if (enabled) {
            for (var user : config.users()) {
                users.put(user.username(), user.password().getBytes(StandardCharsets.UTF_8));
            }
        }
    }

    public boolean isEnabled() {
        return enabled;
    }

    public boolean authenticate(String username, String password) {
        if (!enabled) return true;
        byte[] storedPassword = users.get(username);
        if (storedPassword == null) return false;
        return MessageDigest.isEqual(
            storedPassword,
            password.getBytes(StandardCharsets.UTF_8)
        );
    }

    public Set<String> getUsernames() {
        return Collections.unmodifiableSet(users.keySet());
    }
}
