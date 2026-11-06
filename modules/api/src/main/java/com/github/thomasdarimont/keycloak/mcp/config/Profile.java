package com.github.thomasdarimont.keycloak.mcp.config;

import java.util.Locale;

/**
 * Deployment profile ({@code kc-mcp.profile}): the set of security defaults the server
 * starts with. The individual settings can still be set; the profile decides what they
 * mean when they are not, and {@link #SHARED} refuses to start without the settings a
 * network-reachable server needs.
 */
public enum Profile {
    /**
     * One person's own machine, the default: anonymous MCP endpoint behind DNS rebinding
     * protection, {@code confirm: true} accepted from clients without elicitation,
     * defaults fill in system and realm, outbound hosts unrestricted, encryption of the
     * database storage optional (warned).
     */
    LOCAL,
    /**
     * A server other people reach over the network: callers must authenticate
     * ({@code quarkus.oidc.tenant-enabled=true} and a {@code quarkus.oidc.token.audience}
     * are required), destructive tools are confirmed through elicitation only
     * ({@code confirm-fallback=deny}), destructive tools name their system and realm
     * ({@code explicit-target=destructive}), {@code kc-mcp.allowed-hosts} is required,
     * the admin API's issuer needs an audience, and the database storage needs a
     * {@code secret-key}.
     */
    SHARED;

    public boolean shared() {
        return this == SHARED;
    }

    public static Profile parse(String value) {
        String v = value.trim().toUpperCase(Locale.ROOT).replace('-', '_');
        return switch (v) {
            case "LOCAL", "DEV", "DEVELOPMENT" -> LOCAL;
            case "SHARED", "PROD", "PRODUCTION", "ENTERPRISE" -> SHARED;
            default -> throw new IllegalArgumentException("Unknown profile '" + value + "', expected local or shared");
        };
    }

    public static class Converter implements org.eclipse.microprofile.config.spi.Converter<Profile> {
        @Override
        public Profile convert(String value) {
            return parse(value);
        }
    }
}
