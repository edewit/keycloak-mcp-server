package org.keycloak.mcp.spi;

import org.keycloak.mcp.config.McpServerConfig;
import org.keycloak.mcp.keycloak.KeycloakAdmin;
import org.keycloak.mcp.keycloak.KeycloakSystems;

/**
 * Everything a {@link ToolProvider} gets from the server.
 */
public interface ToolProviderContext {

    /** Admin client of the default system; handlers should prefer {@code ToolCall.kc()} (the call's system). */
    KeycloakAdmin keycloak();

    /** All configured Keycloak systems. */
    KeycloakSystems systems();

    default KeycloakAdmin keycloak(String system) {
        return systems().get(system);
    }

    /** Global server configuration. */
    McpServerConfig serverConfig();

    /** Configuration scoped to this provider: {@code kc-mcp.spi.<id>.*}. */
    ProviderConfig config();
}
