package com.acme.keycloak.mcp;

import com.github.thomasdarimont.keycloak.mcp.access.AccessCheck;
import com.github.thomasdarimont.keycloak.mcp.catalog.Category;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolLevel;
import com.github.thomasdarimont.keycloak.mcp.spi.ConfigProperty;
import com.github.thomasdarimont.keycloak.mcp.spi.ConfigSpec;
import com.github.thomasdarimont.keycloak.mcp.spi.ProviderConfig;
import com.google.auto.service.AutoService;

/**
 * Extension point {@link AccessCheck}, registered globally: runs on every tool call after
 * the realm and role checks. Service accounts ({@code svc-*} by default) may not be
 * changed through the MCP server at all, whatever roles the caller has. Prefix:
 * {@code KC_MCP_SPI_ACCESS_CHECK_ACME_PROTECTED_USERS_PREFIX}.
 */
@AutoService(AccessCheck.class)
public class ProtectedUsersCheck implements AccessCheck {

    /** {@code kc-mcp.spi.access-check.acme-protected-users.prefix} */
    static final ConfigProperty PREFIX = ConfigProperty.string("prefix")
        .withDefault("svc-")
        .withLabel("Protected prefix")
        .withDescription("Users whose name starts with it are refused to change.");

    private String prefix;

    public ProtectedUsersCheck() {
        this("svc-");
    }

    ProtectedUsersCheck(String prefix) {
        this.prefix = prefix;
    }

    @Override
    public String id() {
        return "acme-protected-users";
    }

    @Override
    public ConfigSpec configSpec() {
        return ConfigSpec.of(PREFIX);
    }

    @Override
    public void configure(ProviderConfig config) {
        prefix = config.readString(PREFIX);
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
