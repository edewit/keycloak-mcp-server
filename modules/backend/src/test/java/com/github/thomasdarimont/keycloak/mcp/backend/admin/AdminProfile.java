package com.github.thomasdarimont.keycloak.mcp.backend.admin;

import java.util.Map;

import io.quarkus.test.junit.QuarkusTestProfile;

/** Database storage on an in-memory H2 plus the admin API with a bearer token. */
public class AdminProfile implements QuarkusTestProfile {

    public static final String TOKEN = "admin-test-token";

    @Override
    public Map<String, String> getConfigOverrides() {
        return Map.of("quarkus.datasource.jdbc.url", "jdbc:h2:mem:kc-mcp-admin-test;DB_CLOSE_DELAY=-1",
                "kc-mcp.storage.secret-key", "test-passphrase", "kc-mcp.dynamic-systems", "true",
                "kc-mcp.startup-check", "off", "kc-mcp.admin.enabled", "true", "kc-mcp.admin.token", TOKEN,
                "kc-mcp.allowed-hosts", "127.0.0.1:1,sso.example.com");
    }
}
