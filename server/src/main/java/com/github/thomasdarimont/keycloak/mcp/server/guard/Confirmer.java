package com.github.thomasdarimont.keycloak.mcp.server.guard;

import com.github.thomasdarimont.keycloak.mcp.catalog.ToolSpec;

import io.vertx.core.json.JsonObject;

/**
 * Decides whether a DESTRUCTIVE tool may run. Same instance used by direct tools and
 * {@code execute_tool}.
 */
public interface Confirmer {

    enum Decision {
        /** Go ahead. */
        CONFIRMED,
        /** User (via elicitation) said no. */
        DECLINED,
        /** Nobody could be asked: caller must retry with {@code confirm: true}. */
        CONFIRMATION_REQUIRED
    }

    Decision confirm(ToolSpec spec, String realm, JsonObject args, boolean confirmFlag, InvocationContext ctx);
}
