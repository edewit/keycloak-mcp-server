package com.github.thomasdarimont.keycloak.mcp.spi;

import com.github.thomasdarimont.keycloak.mcp.config.McpServerConfig;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakAdmin;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystems;

/**
 * Everything an extension gets from the server: the Keycloak systems, the server
 * configuration and its own settings ({@code kc-mcp.spi.<spi>.<id>.*}).
 */
public interface ExtensionContext {

    /**
     * Admin client of the default system; handlers should prefer {@code ToolCall.kc()}
     * (the call's system).
     */
    KeycloakAdmin keycloak();

    /** All configured Keycloak systems. */
    KeycloakSystems systems();

    default KeycloakAdmin keycloak(String system) {
        return systems().get(system);
    }

    /** Global server configuration. */
    McpServerConfig serverConfig();

    /** Configuration scoped to this extension: {@code kc-mcp.spi.<spi>.<id>.*}. */
    ProviderConfig config();
}
