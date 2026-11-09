package com.github.thomasdarimont.keycloak.mcp.config;

import java.util.Locale;

/**
 * Whether a Keycloak URL that systems register at runtime (admin API, system
 * repositories) may point at a private, loopback or link-local address
 * ({@code kc-mcp.dynamic-private-hosts}). Static systems are the operator's own
 * configuration and are not checked.
 */
public enum PrivateHosts {
    /**
     * Any address: a Docker hostname such as {@code keycloak:8080} resolves to a private
     * network. Default of profile {@code local}.
     */
    ALLOW,
    /**
     * Only when {@code kc-mcp.allowed-hosts} names the host literally, without a wildcard
     * ({@code keycloak:8080}, not {@code *.internal}): a registered URL cannot reach the
     * server's own network, metadata endpoints or neighbours through a name that resolves
     * there (SSRF). Default of profile {@code shared}.
     */
    LISTED;

    public static PrivateHosts parse(String value) {
        String v = value.trim().toUpperCase(Locale.ROOT).replace('-', '_');
        return switch (v) {
            case "ALLOW", "ANY" -> ALLOW;
            case "LISTED", "DENY", "PUBLIC" -> LISTED;
            default -> throw new IllegalArgumentException(
                    "Unknown dynamic-private-hosts '" + value + "', expected allow or listed");
        };
    }

    public static class Converter implements org.eclipse.microprofile.config.spi.Converter<PrivateHosts> {
        @Override
        public PrivateHosts convert(String value) {
            return parse(value);
        }
    }
}
