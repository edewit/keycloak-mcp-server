package com.github.thomasdarimont.keycloak.mcp.backend.guard;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.junit.jupiter.api.Test;

import com.github.thomasdarimont.keycloak.mcp.catalog.Category;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolResult;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolSpec;
import com.github.thomasdarimont.keycloak.mcp.keycloak.AccessSettings;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystem;
import com.github.thomasdarimont.keycloak.mcp.keycloak.RealmSettings;
import com.github.thomasdarimont.keycloak.mcp.keycloak.ToolSettings;

import io.vertx.core.json.JsonObject;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Confirmation of tools that are not destructive, where the server, a system or a realm
 * asks for it.
 */
class ConfirmationPerSystemTest {

    static ToolSpec tool(String name, String level, String... formerly) {
        ToolSpec.Builder b = ToolSpec.builder(name)
            .title("t")
            .description("d")
            .category(Category.USERS)
            .formerly(formerly)
            .handler(c -> ToolResult.ok(""));
        return switch (level) {
            case "read" -> b.read().build();
            case "write" -> b.write().build();
            default -> b.destructive().build();
        };
    }

    static final ToolSpec GET = tool("keycloak_user_get", "read");
    static final ToolSpec DISABLE = tool("keycloak_user_set_enabled", "write");
    static final ToolSpec LOGOUT = tool("keycloak_user_logout", "write", "keycloak_user_signout");
    static final ToolSpec DELETE = tool("keycloak_user_delete", "destructive");

    static ToolSettings tools(String json) {
        return ToolSettings.fromJson(new JsonObject(json), "tools.");
    }

    final AccessPolicy policy = new AccessPolicy(false, List.of());

    @Test
    void destructiveToolsAlwaysReadToolsNever() {
        KeycloakSystem relaxed = KeycloakSystem.builder("dev", "https://sso").build();
        assertTrue(policy.needsConfirmation(DELETE, "acme", relaxed));
        assertFalse(policy.needsConfirmation(DISABLE, "acme", relaxed));
        KeycloakSystem everything = KeycloakSystem.builder("prod", "https://sso")
            .tools(tools("{\"confirmWrites\": true, \"confirm\": [\"user_get\"]}"))
            .build();
        assertFalse(policy.needsConfirmation(GET, "acme", everything), "reading changes nothing to confirm");
    }

    @Test
    void perSystemAndRealm() {
        KeycloakSystem prod = KeycloakSystem.builder("prod", "https://sso")
            .tools(tools("{\"confirm\": [\"user_set_enabled\"]}"))
            .realm(new RealmSettings("customers", Optional.empty(), Optional.empty(), Optional.empty(),
                    Optional.empty(), AccessSettings.NONE, tools("{\"confirmWrites\": true}")))
            .build();

        assertTrue(policy.needsConfirmation(DISABLE, "other", prod), "the system's list");
        assertFalse(policy.needsConfirmation(LOGOUT, "other", prod));
        assertTrue(policy.needsConfirmation(LOGOUT, "customers", prod), "every write in that realm");
        assertFalse(policy.needsConfirmation(DISABLE, "acme", KeycloakSystem.builder("dev", "https://sso").build()));
    }

    @Test
    void serverWideAndAcrossRenames() {
        AccessPolicy server = new AccessPolicy(false, List.of()).confirmation(List.of("user_signout"), false);
        KeycloakSystem dev = KeycloakSystem.builder("dev", "https://sso").build();

        assertTrue(server.needsConfirmation(LOGOUT, "acme", dev), "named by its former name");
        assertTrue(new AccessPolicy(false, List.of()).confirmation(List.of(), true)
            .needsConfirmation(DISABLE, "acme", dev));
    }

    @Test
    void theKeyIsConfirmInASection() {
        ToolSettings ok = ToolSettings.fromFlat(Map.of("confirm", "user_set_enabled,user_logout"),
                "kc-mcp.systems.prod.realms.customers.tools.");
        assertTrue(ok.confirm().orElseThrow().contains("user_logout"));
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> ToolSettings
            .fromFlat(Map.of("confirm-tools", "user_set_enabled"), "kc-mcp.systems.prod.realms.customers.tools."));
        assertTrue(e.getMessage().contains("confirm-tools is not a tool setting"), e.getMessage());
    }
}
