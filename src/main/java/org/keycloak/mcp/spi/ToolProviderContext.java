package org.keycloak.mcp.spi;

import org.keycloak.mcp.config.McpServerConfig;
import org.keycloak.mcp.keycloak.KeycloakAdmin;

/**
 * Everything a {@link ToolProvider} gets from the server.
 */
public interface ToolProviderContext {

    /** Shared, lazily connected admin client. */
    KeycloakAdmin keycloak();

    /** Global server configuration. */
    McpServerConfig serverConfig();

    /** Configuration scoped to this provider: {@code kc-mcp.spi.<id>.*}. */
    ProviderConfig config();
}
