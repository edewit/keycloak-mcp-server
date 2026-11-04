package com.github.thomasdarimont.keycloak.mcp.config;

import java.util.Locale;

/**
 * Whose credentials reach the Keycloak Admin API.
 */
public enum DelegationMode {
    /** The server's own service account / admin user. Default. */
    OFF,
    /**
     * The caller's access token is forwarded unchanged: the MCP endpoint requires an
     * OAuth login and every admin call runs with that user's realm-management roles.
     * Needs {@code quarkus.oidc.tenant-enabled=true}.
     */
    FORWARD;

    public static DelegationMode parse(String value) {
        String v = value.trim().toUpperCase(Locale.ROOT).replace('-', '_');
        return switch (v) {
            case "OFF", "NONE", "SERVICE_ACCOUNT" -> OFF;
            case "FORWARD" -> FORWARD;
            default ->
                throw new IllegalArgumentException("Unknown delegation mode '" + value + "', expected off or forward");
        };
    }

    public static class Converter implements org.eclipse.microprofile.config.spi.Converter<DelegationMode> {
        @Override
        public DelegationMode convert(String value) {
            return parse(value);
        }
    }
}
