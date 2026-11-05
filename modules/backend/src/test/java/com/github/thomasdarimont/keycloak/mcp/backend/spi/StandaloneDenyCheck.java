package com.github.thomasdarimont.keycloak.mcp.backend.spi;

import com.github.thomasdarimont.keycloak.mcp.access.AccessCheck;

import com.google.auto.service.AutoService;

/**
 * A global access check registered on its own through the ServiceLoader, without a tool
 * provider or CDI: refuses any tool called with {@code name=standalone}.
 */
@AutoService(AccessCheck.class)
public class StandaloneDenyCheck implements AccessCheck {

    @Override
    public Decision check(Context context) {
        return "standalone".equals(context.arg("name"))
                ? Decision.deny("standalone_denied", "Refused by the standalone check.") : Decision.allow();
    }

}
