package com.acme.keycloak.mcp;

import java.util.Map;

import com.github.thomasdarimont.keycloak.mcp.access.AccessCheck;
import com.github.thomasdarimont.keycloak.mcp.catalog.Category;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolLevel;
import com.github.thomasdarimont.keycloak.mcp.spi.ProviderConfig;
import com.google.auto.service.AutoService;

/**
 * Extension point {@link AccessCheck}, registered globally: runs on every tool call after
 * the realm and role checks. Service accounts ({@code svc-*} by default) may not be
 * changed through the MCP server at all, whatever roles the caller has. Prefix:
 * {@code KC_MCP_SPI_ACME_PROTECTED_USERS_PREFIX}.
 */
@AutoService(AccessCheck.class)
public class ProtectedUsersCheck implements AccessCheck {

    private final String prefix;

    public ProtectedUsersCheck() {
        this(ProviderConfig.forExtension("acme-protected-users", Map.of()).get("prefix", "svc-"));
    }

    ProtectedUsersCheck(String prefix) {
        this.prefix = prefix;
    }

    @Override
    public String id() {
        return "acme-protected-users";
    }

    @Override
    public Decision check(Context c) {
        if (c.tool().level() == ToolLevel.READ || c.tool().category() != Category.USERS) {
            return Decision.allow();
        }
        for (String arg : new String[] { "username", "id", "user" }) {
            String value = c.arg(arg);
            if (value != null && value.startsWith(prefix)) {
                return Decision.deny("protected_user",
                        "Users named " + prefix + "* are service accounts managed by the platform team.");
            }
        }
        return Decision.allow();
    }
}
