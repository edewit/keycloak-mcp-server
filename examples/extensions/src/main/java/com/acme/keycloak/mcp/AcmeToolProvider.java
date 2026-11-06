package com.acme.keycloak.mcp;

import java.util.List;

import org.keycloak.representations.idm.GroupRepresentation;
import org.keycloak.representations.idm.UserRepresentation;

import com.github.thomasdarimont.keycloak.mcp.access.AccessCheck;
import com.github.thomasdarimont.keycloak.mcp.catalog.Category;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolResult;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolSpec;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakAdmin;
import com.github.thomasdarimont.keycloak.mcp.keycloak.Views;
import com.github.thomasdarimont.keycloak.mcp.tools.AbstractToolProvider;
import com.github.thomasdarimont.keycloak.mcp.tools.ToolProvider;
import com.github.thomasdarimont.keycloak.mcp.tools.ToolProviderContext;
import com.google.auto.service.AutoService;

/**
 * Extension point {@link ToolProvider}: two company tools next to the built-in catalog.
 * They get search, exposure modes, argument validation, realm and role checks,
 * confirmation and the audit log for free. Settings: {@code kc-mcp.spi.acme.*} /
 * {@code KC_MCP_SPI_ACME_*}.
 */
@AutoService(ToolProvider.class)
public class AcmeToolProvider extends AbstractToolProvider {

    @Override
    public String id() {
        return "acme";
    }

    @Override
    public String displayName() {
        return "ACME tools";
    }

    @Override
    public String description() {
        return "Company specific helpers: user summary and offboarding.";
    }

    @Override
    public List<ToolSpec> tools(ToolProviderContext ctx) {
        String company = ctx.config().get("company", "ACME"); // kc-mcp.spi.acme.company
        return List.of(
                // READ: needs view-users in the realm, visible to everyone who has it
                tool("keycloak_acme_user_summary").title(company + ": user summary")
                    .description("One-line summary of a user: status, email, groups.")
                    .category(Category.USERS)
                    .read()
                    .roles("view-users")
                    .synonyms("overview", "profile", "who is")
                    .schema(schema().string("username", USER_ID).required())
                    .handler(call -> {
                        KeycloakAdmin kc = call.kc();
                        UserRepresentation u = kc.findUser(call.realm(), call.str("username"));
                        List<String> groups = kc.user(call.realm(), u.getId())
                            .groups()
                            .stream()
                            .map(GroupRepresentation::getPath)
                            .toList();
                        return ToolResult.ok(java.util.Map.of("user", Views.user(u), "groups", groups, "summary",
                                u.getUsername() + " is " + (Boolean.TRUE.equals(u.isEnabled()) ? "enabled" : "disabled")
                                        + ", " + groups.size() + " group(s)"));
                    })
                    .build(),
                // DESTRUCTIVE: confirmation (TicketConfirmer accepts a change ticket
                // instead of a prompt),
                // a per-tool access check, manage-users required, refused when the server
                // acts for a user
                tool("keycloak_acme_user_offboard").title(company + ": offboard user")
                    .description("Disables a user, ends their sessions and removes them from all groups.")
                    .category(Category.USERS)
                    .destructive()
                    .roles("manage-users")
                    .synonyms("leaver", "deprovision", "remove access")
                    .schema(schema().string("username", USER_ID)
                        .required()
                        .string("ticket", "Change ticket (ACME-123); replaces the confirmation prompt"))
                    .access(c -> "admin".equals(c.arg("username"))
                            ? AccessCheck.Decision.deny("protected_user", "The admin account is never offboarded.")
                            : AccessCheck.Decision.allow())
                    .handler(call -> {
                        KeycloakAdmin kc = call.kc();
                        UserRepresentation u = kc.findUser(call.realm(), call.str("username"));
                        var user = kc.user(call.realm(), u.getId());
                        u.setEnabled(false);
                        user.update(u);
                        user.logout();
                        List<GroupRepresentation> groups = user.groups();
                        groups.forEach(g -> user.leaveGroup(g.getId()));
                        return ToolResult.done("User offboarded: disabled, sessions ended, groups left.", "username",
                                u.getUsername(), "groupsLeft", groups.size(), "ticket", call.str("ticket"));
                    })
                    .build());
    }
}
