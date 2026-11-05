package com.github.thomasdarimont.keycloak.mcp.server;

import java.util.Map;
import java.util.Set;

import org.eclipse.microprofile.config.spi.ConfigSource;

import com.google.auto.service.AutoService;

/**
 * Baseline configuration of every test, pinned above the environment (ordinal 350: above
 * env vars at 300, below the system properties at 400 that {@code QuarkusTestProfile}s
 * and {@code QuarkusTestResource}s use). A shell that still has one of the demo env files
 * sourced ({@code KC_MCP_CLIENT_SECRET}, {@code KC_MCP_DELEGATION},
 * {@code QUARKUS_OIDC_TENANT_ENABLED}, ...) must not change what the tests see. Empty
 * values clear a leaked setting: SmallRye treats them as absent for optional properties.
 */
@AutoService(ConfigSource.class)
public class TestConfig implements ConfigSource {

    private static final Map<String, String> VALUES = Map.ofEntries(
            // tests never talk to a real Keycloak: a closed port fails fast with
            // keycloak_unreachable
            Map.entry("kc-mcp.url", "http://127.0.0.1:1"), Map.entry("kc-mcp.grant-type", "password"),
            Map.entry("kc-mcp.auth-realm", "master"), Map.entry("kc-mcp.username", "admin"),
            Map.entry("kc-mcp.password", "admin"), Map.entry("kc-mcp.client-id", ""),
            Map.entry("kc-mcp.client-secret", ""), Map.entry("kc-mcp.client-auth", ""),
            Map.entry("kc-mcp.jwt.key-file", ""), Map.entry("kc-mcp.jwt.algorithm", "RS256"),
            Map.entry("kc-mcp.delegation", "off"), Map.entry("kc-mcp.default-system", ""),
            Map.entry("kc-mcp.default-realm", ""), Map.entry("kc-mcp.allowed-realms", ""),
            Map.entry("kc-mcp.allowed-hosts", ""), Map.entry("kc-mcp.denied-tools", ""),
            Map.entry("kc-mcp.read-only", "false"), Map.entry("kc-mcp.tool-exposure", "hybrid"),
            Map.entry("kc-mcp.startup-check", "off"),
            // provider settings are a map of plain strings, so they take real values
            // rather than blanks
            Map.entry("kc-mcp.spi.policies.group-scope", "off"), Map.entry("kc-mcp.spi.policies.no-escalation", "true"),
            Map.entry("quarkus.oidc.tenant-enabled", "false"), Map.entry("quarkus.oidc.token.audience", ""));

    @Override
    public Set<String> getPropertyNames() {
        return VALUES.keySet();
    }

    @Override
    public String getValue(String propertyName) {
        return VALUES.get(propertyName);
    }

    @Override
    public String getName() {
        return "keycloak-mcp test baseline";
    }

    @Override
    public int getOrdinal() {
        return 350;
    }
}
