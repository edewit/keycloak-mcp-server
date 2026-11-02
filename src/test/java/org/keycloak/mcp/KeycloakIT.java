package org.keycloak.mcp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import io.quarkus.test.common.QuarkusTestResource;
import io.quarkus.test.junit.QuarkusTest;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

/**
 * Happy paths of the ported USERS / GROUPS / ROLES / REALM tools against a real Keycloak, driven through the MCP
 * endpoint in direct mode. Run with {@code ./mvnw verify -DskipITs=false}.
 */
@QuarkusTest
@QuarkusTestResource(value = KeycloakTestResource.class, restrictToAnnotatedClass = true)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class KeycloakIT {

    static final String REALM = "master";
    static McpClient mcp;
    static String userId;
    static String groupId;

    @BeforeEach
    void connect() {
        if (mcp == null) {
            mcp = new McpClient().initialize(false);
        }
    }

    static JsonObject call(String tool, JsonObject args) {
        JsonObject result = mcp.callTool(tool, args.put("realm", REALM));
        JsonObject body = McpClient.text(result);
        assertFalse(result.getBoolean("isError", false), tool + " -> " + body.encode());
        return body;
    }

    static JsonObject error(String tool, JsonObject args) {
        JsonObject result = mcp.callTool(tool, args.put("realm", REALM));
        assertTrue(result.getBoolean("isError", false), tool + " should fail");
        return McpClient.text(result);
    }

    @Test
    @Order(1)
    void serverInfoAndRealmConfig() {
        JsonObject info = McpClient.text(mcp.callTool("keycloak_server_info", new JsonObject()));
        assertTrue(info.getString("version").startsWith("26."), info.encode());
        JsonObject cfg = call("keycloak_realm_get_config", new JsonObject());
        assertEquals("master", cfg.getString("realm"));
        assertEquals("browser", cfg.getJsonObject("flows").getString("browserFlow"));
    }

    @Test
    @Order(2)
    void userLifecycle() {
        JsonObject created = call("keycloak_user_create", new JsonObject()
                .put("username", "alice").put("email", "alice@example.com").put("firstName", "Alice")
                .put("password", "secret1!").put("temporary", "true"));
        userId = created.getString("id");
        assertNotNull(userId);

        JsonObject dup = error("keycloak_user_create", new JsonObject().put("username", "alice"));
        assertEquals("conflict", dup.getString("error"));

        JsonObject search = call("keycloak_user_search", new JsonObject().put("search", "ali"));
        assertEquals("alice", search.getJsonArray("items").getJsonObject(0).getString("username"));
        JsonObject byEmail = call("keycloak_user_search", new JsonObject().put("email", "alice@example.com"));
        assertEquals(1, byEmail.getInteger("count"));

        // id or username both resolve
        JsonObject get = call("keycloak_user_get", new JsonObject().put("id", "alice"));
        assertEquals(userId, get.getString("id"));
        assertEquals("Alice", get.getString("firstName"));
        assertTrue(get.getJsonArray("requiredActions").contains("UPDATE_PASSWORD"));

        JsonObject upd = call("keycloak_user_update", new JsonObject().put("id", userId).put("lastName", "Liddell")
                .put("attributes", new JsonObject().put("department", "R&D")));
        assertTrue(upd.getJsonArray("changed").contains("attributes"));
        // a fresh KC 26 realm drops undeclared attributes (user profile); the tool must say so instead of lying
        assertTrue(upd.getString("warning", "").contains("department"), upd.encode());
        JsonObject get2 = call("keycloak_user_get", new JsonObject().put("id", userId));
        assertEquals("Liddell", get2.getString("lastName"));

        call("keycloak_user_set_enabled", new JsonObject().put("id", "alice").put("enabled", false));
        JsonObject disabled = call("keycloak_user_search", new JsonObject().put("username", "alice"));
        assertEquals(false, disabled.getJsonArray("items").getJsonObject(0).getBoolean("enabled"));
        call("keycloak_user_set_enabled", new JsonObject().put("id", "alice").put("enabled", "yes"));

        JsonObject missing = error("keycloak_user_get", new JsonObject().put("id", "nobody"));
        assertEquals("not_found", missing.getString("error"));

        call("keycloak_user_reset_password", new JsonObject().put("id", userId).put("password", "newpass1!")
                .put("confirm", true));
        JsonObject sessions = call("keycloak_user_sessions_list", new JsonObject().put("id", userId));
        assertEquals(0, sessions.getInteger("count"));
        call("keycloak_user_logout", new JsonObject().put("id", userId).put("confirm", true));
    }

    @Test
    @Order(3)
    void groupsAndMembership() {
        JsonObject g = call("keycloak_group_create", new JsonObject().put("name", "admins"));
        groupId = g.getString("id");
        assertEquals("/admins", g.getString("path"));
        JsonObject sub = call("keycloak_group_create", new JsonObject().put("name", "ops").put("parentId", "admins"));
        assertEquals("/admins/ops", sub.getString("path"));

        JsonObject list = call("keycloak_group_list", new JsonObject().put("search", "adm"));
        assertEquals("admins", list.getJsonArray("items").getJsonObject(0).getString("name"));

        call("keycloak_group_member_add", new JsonObject().put("groupId", "/admins/ops").put("userId", "alice"));
        JsonObject members = call("keycloak_group_members_list", new JsonObject().put("groupId", sub.getString("id")));
        assertEquals("alice", members.getJsonArray("items").getJsonObject(0).getString("username"));
        JsonObject userGroups = call("keycloak_user_groups_list", new JsonObject().put("userId", userId));
        assertEquals("/admins/ops", userGroups.getJsonArray("items").getJsonObject(0).getString("path"));

        call("keycloak_group_role_assign", new JsonObject().put("groupId", groupId).put("role", "offline_access"));
        JsonObject roles = call("keycloak_user_roles_get", new JsonObject().put("userId", "alice"));
        assertTrue(roles.getJsonArray("effectiveRealmRoles").contains("offline_access"), roles.encode());

        call("keycloak_group_member_remove", new JsonObject().put("groupId", "ops").put("userId", userId)
                .put("confirm", true));
        assertEquals(0, call("keycloak_group_members_list", new JsonObject().put("groupId", sub.getString("id")))
                .getInteger("count"));
    }

    @Test
    @Order(4)
    void roles() {
        JsonObject list = call("keycloak_role_list", new JsonObject());
        JsonArray names = new JsonArray(list.getJsonArray("items").stream()
                .map(o -> ((JsonObject) o).getString("name")).toList());
        assertTrue(names.contains("admin"), names.encode());

        call("keycloak_user_role_assign", new JsonObject().put("userId", "alice").put("role", "admin"));
        JsonObject roles = call("keycloak_user_roles_get", new JsonObject().put("userId", userId));
        assertTrue(roles.getJsonArray("realmRoles").contains("admin"));
        call("keycloak_user_role_unassign", new JsonObject().put("userId", "alice").put("role", "admin")
                .put("confirm", true));
        assertFalse(call("keycloak_user_roles_get", new JsonObject().put("userId", userId))
                .getJsonArray("realmRoles").contains("admin"));

        JsonObject clientRoles = call("keycloak_client_roles_list", new JsonObject().put("clientId", "master-realm"));
        assertEquals("master-realm", clientRoles.getString("clientId"));
        assertTrue(clientRoles.getInteger("count") > 5);

        call("keycloak_user_client_role_assign", new JsonObject().put("userId", "alice")
                .put("clientId", "master-realm").put("role", "view-users"));
        JsonObject ucr = call("keycloak_user_client_roles_get", new JsonObject().put("userId", "alice")
                .put("clientId", "master-realm"));
        assertTrue(ucr.getJsonArray("roles").contains("view-users"));
        assertTrue(ucr.getJsonArray("effectiveRoles").contains("query-users"));
        call("keycloak_user_client_role_unassign", new JsonObject().put("userId", "alice")
                .put("clientId", "master-realm").put("role", "view-users").put("confirm", true));

        JsonObject unknownRole = error("keycloak_user_role_assign", new JsonObject().put("userId", "alice")
                .put("role", "does-not-exist"));
        assertEquals("not_found", unknownRole.getString("error"));
    }

    @Test
    @Order(5)
    void deleteWithGuards() {
        JsonObject mismatch = error("keycloak_user_delete", new JsonObject().put("id", userId).put("username", "bob")
                .put("confirm", true));
        assertEquals("username_mismatch", mismatch.getString("error"));
        JsonObject needsConfirm = error("keycloak_user_delete", new JsonObject().put("id", userId)
                .put("username", "alice"));
        assertEquals("confirmation_required", needsConfirm.getString("error"));
        call("keycloak_user_delete", new JsonObject().put("id", userId).put("username", "alice").put("confirm", true));
        assertEquals("not_found", error("keycloak_user_get", new JsonObject().put("id", userId)).getString("error"));

        call("keycloak_group_delete", new JsonObject().put("id", groupId).put("confirm", true));
        assertEquals(0, call("keycloak_group_list", new JsonObject().put("search", "admins")).getInteger("count"));
    }
}
