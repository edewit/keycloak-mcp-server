package org.keycloak.mcp.tools;

import org.keycloak.mcp.catalog.InputSchema;
import org.keycloak.mcp.catalog.ToolSpec;
import org.keycloak.mcp.keycloak.KeycloakAdmin;
import org.keycloak.mcp.spi.ToolProvider;
import org.keycloak.mcp.spi.ToolProviderContext;

/**
 * Base class for the built-in providers: keeps the admin client from {@link #init(ToolProviderContext)} and offers
 * a few shared schema snippets.
 */
public abstract class AbstractToolProvider implements ToolProvider {

    protected KeycloakAdmin kc;

    @Override
    public void init(ToolProviderContext context) {
        this.kc = context.keycloak();
    }

    protected static ToolSpec.Builder tool(String name) {
        return ToolSpec.builder(name);
    }

    protected static InputSchema.Builder schema() {
        return InputSchema.builder();
    }

    protected static final String USER_ID = "User id (UUID); a username is accepted too";
    protected static final String GROUP_ID = "Group id (UUID); a full path like /parent/child or a unique name is accepted too";
    protected static final String CLIENT_ID = "Client's internal id (UUID) or its clientId, e.g. my-app";
}
