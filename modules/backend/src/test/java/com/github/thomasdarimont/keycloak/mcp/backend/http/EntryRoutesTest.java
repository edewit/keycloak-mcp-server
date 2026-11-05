package com.github.thomasdarimont.keycloak.mcp.backend.http;

import java.util.Optional;

import org.junit.jupiter.api.Test;

import com.github.thomasdarimont.keycloak.mcp.backend.McpClient;
import com.github.thomasdarimont.keycloak.mcp.backend.guard.EntryBinding;

import io.quarkus.test.junit.QuarkusTest;
import io.vertx.core.json.JsonObject;

import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The single static system of the tests is called {@code default}. */
@QuarkusTest
class EntryRoutesTest {

    @Test
    void pathsParseIntoBindings() {
        assertEquals(Optional.of(new EntryBinding("prod", null)),
                EntryRoutes.resolveEntryBinding("/mcp/systems/prod", "/mcp"));
        assertEquals(Optional.of(new EntryBinding("prod", "customers")),
                EntryRoutes.resolveEntryBinding("/mcp/systems/prod/customers/", "/mcp"));
        assertTrue(EntryRoutes.resolveEntryBinding("/mcp", "/mcp").isEmpty());
        assertTrue(EntryRoutes.resolveEntryBinding("/mcp/systems/", "/mcp").isEmpty());
        assertTrue(EntryRoutes.resolveEntryBinding("/mcp/systems/a/b/c", "/mcp").isEmpty());
        assertTrue(EntryRoutes.resolveEntryBinding("/mcp/systems/bad name", "/mcp").isEmpty());
        assertEquals(Optional.of(new EntryBinding("x", null)),
                EntryRoutes.resolveEntryBinding("/api/systems/x", "api/"));
    }

    @Test
    void systemEntryPinsTheSystem() {
        McpClient mcp = new McpClient().path("/mcp/systems/default").initialize(false);
        JsonObject who = McpClient.text(mcp.callTool("whoami", new JsonObject()));
        assertEquals("default", who.getJsonObject("entry").getString("system"), who.encode());
        assertEquals("default", who.getString("system"), who.encode());

        JsonObject same = McpClient.text(mcp.callTool("keycloak_user_search",
                new JsonObject().put("system", "default").put("realm", "demo").put("search", "bob")));
        assertEquals("keycloak_unreachable", same.getString("error"), "pinned system accepted: " + same.encode());
        JsonObject other = McpClient.text(mcp.callTool("keycloak_user_search",
                new JsonObject().put("system", "other").put("realm", "demo").put("search", "bob")));
        assertEquals("entry_mismatch", other.getString("error"), other.encode());
        assertEquals("default", other.getJsonObject("entry").getString("system"));
        JsonObject whoOther = McpClient.text(mcp.callTool("whoami", new JsonObject().put("system", "other")));
        assertEquals("entry_mismatch", whoOther.getString("error"), whoOther.encode());
    }

    @Test
    void realmEntryPinsTheRealmToo() {
        McpClient mcp = new McpClient().path("/mcp/systems/default/demo").initialize(false);
        JsonObject who = McpClient.text(mcp.callTool("whoami", new JsonObject()));
        assertEquals("demo", who.getJsonObject("entry").getString("realm"), who.encode());

        JsonObject noRealm = McpClient
            .text(mcp.callTool("keycloak_user_search", new JsonObject().put("search", "bob")));
        assertFalse("realm_required".equals(noRealm.getString("error")), "realm comes from the entry: " + noRealm);
        assertEquals("keycloak_unreachable", noRealm.getString("error"), noRealm.encode());
        JsonObject otherRealm = McpClient
            .text(mcp.callTool("keycloak_user_search", new JsonObject().put("realm", "other").put("search", "bob")));
        assertEquals("entry_mismatch", otherRealm.getString("error"), otherRealm.encode());
        // global tools ignore the realm pin
        JsonObject info = McpClient.text(mcp.callTool("keycloak_server_info", new JsonObject()));
        assertNull(info.getJsonObject("entry"), info.encode());
    }

    @Test
    void unknownSystemAndMalformedPaths() {
        McpClient mcp = new McpClient().path("/mcp/systems/nope").initialize(false);
        JsonObject who = McpClient.text(mcp.callTool("whoami", new JsonObject()));
        assertEquals("unknown_system", who.getString("error"), who.encode());
        given().post("/mcp/systems/bad%20name").then().statusCode(404);
        given().post("/mcp/systems/a/b/c").then().statusCode(404);
    }
}
