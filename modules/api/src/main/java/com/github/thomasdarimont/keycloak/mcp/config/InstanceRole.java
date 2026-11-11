package com.github.thomasdarimont.keycloak.mcp.config;

import java.util.Locale;

/**
 * What one instance of the server serves ({@code kc-mcp.instance-role}), for deployments
 * that split the MCP endpoint from the admin API and the management UI, all instances on
 * one database. The role sets the defaults of {@code kc-mcp.mcp.enabled},
 * {@code kc-mcp.admin.enabled} and {@code kc-mcp.ui.enabled}; setting one of them against
 * the role stops the start.
 */
public enum InstanceRole {
    /**
     * Everything this configuration switches on, the default: the MCP endpoint, plus the
     * admin API and the UI when they are enabled.
     */
    ALL,
    /**
     * The MCP endpoint only, for the instances behind the public ingress: no admin API,
     * no management UI, whatever else is configured.
     */
    MCP,
    /**
     * The admin API (on by default) and, when enabled, the management UI, for an instance
     * on the internal network: the MCP endpoint and its entries answer a plain 404.
     */
    ADMIN;

    /** Whether this instance may serve the MCP endpoint. */
    public boolean servesMcp() {
        return this != ADMIN;
    }

    /** Whether this instance may serve the admin API and the management UI. */
    public boolean servesAdmin() {
        return this != MCP;
    }

    public String id() {
        return name().toLowerCase(Locale.ROOT);
    }

    public static InstanceRole parse(String value) {
        return switch (value.trim().toLowerCase(Locale.ROOT)) {
            case "all" -> ALL;
            case "mcp" -> MCP;
            case "admin" -> ADMIN;
            default ->
                throw new IllegalArgumentException("Unknown instance role '" + value + "', expected all, mcp or admin");
        };
    }

    public static class Converter implements org.eclipse.microprofile.config.spi.Converter<InstanceRole> {
        @Override
        public InstanceRole convert(String value) {
            return parse(value);
        }
    }
}
