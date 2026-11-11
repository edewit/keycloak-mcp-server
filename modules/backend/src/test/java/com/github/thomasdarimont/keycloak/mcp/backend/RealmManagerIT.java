package com.github.thomasdarimont.keycloak.mcp.backend;

import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import io.quarkus.test.common.QuarkusTestResource;
import io.quarkus.test.junit.QuarkusTest;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * "realm-manager" access level: client_credentials against a service account holding only
 * view-users and view-clients in realm mgr. Tools needing other roles must be hidden and
 * refused before reaching Keycloak.
 */
@QuarkusTest
@QuarkusTestResource(value = RealmManagerTestResource.class, restrictToAnnotatedClass = true)
class RealmManagerIT {

    McpClient mcp;

    @BeforeEach
    void connect() {
        mcp = new McpClient().initialize(false);
    }

    @Test
    void onlyToolsCoveredByTheTokenRolesAreVisible() {
        // first call runs role discovery; afterwards tools/list reflects it
        McpClient.text(mcp.callTool("keycloak_user_search", new JsonObject()));
        JsonArray tools = mcp.listTools();
        List<String> names = tools.stream().map(t -> ((JsonObject) t).getString("name")).toList();
        assertTrue(names.containsAll(List.of("keycloak_user_search", "keycloak_user_get", "keycloak_client_get",
                "keycloak_client_roles_list", "keycloak_server_info")), names.toString());
        assertFalse(names.contains("keycloak_user_create"), names.toString());
        assertFalse(names.contains("keycloak_user_set_enabled"));
        assertFalse(names.contains("keycloak_realm_get_config"), "needs view-realm");
        assertFalse(names.contains("keycloak_events_login"), "needs view-events");
        assertFalse(names.contains("keycloak_role_list"), "needs view-realm");
    }

    @Test
    void readToolsWorkWithDefaultRealm() {
        JsonObject r = McpClient.text(mcp.callTool("keycloak_user_search", new JsonObject().put("username", "bob")));
        assertEquals("bob", r.getJsonArray("items").getJsonObject(0).getString("username"));
        JsonObject c = McpClient.text(mcp.callTool("keycloak_client_get", new JsonObject().put("clientId", "mcp-mgr")));
        assertEquals(true, c.getBoolean("serviceAccountsEnabled"));
    }

    @Test
    void toolsBeyondTheRolesAreRefusedLocally() {
        JsonObject result = mcp.callTool("keycloak_user_set_enabled",
                new JsonObject().put("id", "bob").put("enabled", false));
        assertTrue(result.getBoolean("isError"));
        JsonObject r = McpClient.text(result);
        assertEquals("forbidden", r.getString("error"));
        assertEquals("manage-users", r.getJsonArray("missingRoles").getString(0));
        JsonObject cfg = McpClient.text(mcp.callTool("keycloak_realm_get_config", new JsonObject()));
        assertEquals("forbidden", cfg.getString("error"));
        // bob is still enabled
        assertEquals(true, McpClient.text(mcp.callTool("keycloak_user_get", new JsonObject().put("id", "bob")))
            .getBoolean("enabled"));
    }

    @Test
    void searchHidesUnusableToolsAndRealmAllowListHolds() {
        JsonObject s = McpClient.text(mcp.callTool("search_tools", new JsonObject().put("query", "disable user")));
        List<String> names = s.getJsonArray("tools").stream().map(t -> ((JsonObject) t).getString("name")).toList();
        assertFalse(names.contains("keycloak_user_set_enabled"), names.toString());
        assertTrue(names.contains("keycloak_user_search"), names.toString());
        JsonObject other = McpClient
            .text(mcp.callTool("keycloak_user_search", new JsonObject().put("realm", "master")));
        assertEquals("realm_not_allowed", other.getString("error"));
    }
}
