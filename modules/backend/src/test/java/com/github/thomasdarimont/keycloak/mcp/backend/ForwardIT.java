package com.github.thomasdarimont.keycloak.mcp.backend;

import org.junit.jupiter.api.Test;

import io.quarkus.test.common.QuarkusTestResource;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.response.Response;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Delegation mode {@code forward} against a real Keycloak: the endpoint challenges
 * anonymous clients the way the MCP authorization spec expects, and every admin call runs
 * with the caller's own roles. Run with {@code ./mvnw verify -DskipITs=false}.
 */
@QuarkusTest
@QuarkusTestResource(value = ForwardTestResource.class, restrictToAnnotatedClass = true)
class ForwardIT {

    private static McpClient as(String user) {
        return new McpClient().bearer(ForwardTestResource.token("mcp-consumer", user, user)).initialize(false);
    }

    @Test
    void adminApiAcceptsAccessTokensOfTheTrustedIssuerWithTheRole() {
        given().get("/admin/systems").then().statusCode(401).header("WWW-Authenticate", startsWith("Bearer"));
        // a realm admin's token opens the API ...
        given().header("Authorization", "Bearer " + ForwardTestResource.token("mcp-consumer", "alice", "alice"))
            .get("/admin/systems")
            .then()
            .statusCode(200)
            .body("systems.alias", hasItem("default"));
        // ... a viewer's does not, nor a token without the audience
        given().header("Authorization", "Bearer " + ForwardTestResource.token("mcp-consumer", "carol", "carol"))
            .get("/admin/systems")
            .then()
            .statusCode(403)
            .body("error", equalTo("forbidden"));
        given().header("Authorization", "Bearer " + ForwardTestResource.token("other-app", "alice", "alice"))
            .get("/admin/systems")
            .then()
            .statusCode(401);
        given().header("Authorization", "Bearer not-a-token").get("/admin/systems").then().statusCode(401);
        // registering needs a mutable repository, which this profile lacks
        given().header("Authorization", "Bearer " + ForwardTestResource.token("mcp-consumer", "alice", "alice"))
            .contentType("application/json")
            .body("{\"url\": \"" + ForwardTestResource.base + "\"}")
            .put("/admin/systems/acme")
            .then()
            .statusCode(503)
            .body("error", equalTo("no_mutable_repository"));
        // and secrets a vault that stores them, which the file vault does not
        given().header("Authorization", "Bearer " + ForwardTestResource.token("mcp-consumer", "alice", "alice"))
            .contentType("application/json")
            .body("{\"value\": \"s3cr3t\"}")
            .put("/admin/secrets/acme/client-secret")
            .then()
            .statusCode(409)
            .body("error", equalTo("vault_read_only"));
        given().header("Authorization", "Bearer " + ForwardTestResource.token("mcp-consumer", "alice", "alice"))
            .get("/admin/secrets")
            .then()
            .statusCode(200)
            .body("vault", equalTo("file-key-vault"))
            .body("writable", equalTo(false));
    }

    @Test
    void anonymousRequestsGetTheOAuthChallenge() {
        Response r = given().header("Accept", "application/json, text/event-stream")
            .header("Content-Type", "application/json")
            .body(new JsonObject().put("jsonrpc", "2.0")
                .put("id", 1)
                .put("method", "initialize")
                .put("params",
                        new JsonObject().put("protocolVersion", "2025-06-18")
                            .put("capabilities", new JsonObject())
                            .put("clientInfo", new JsonObject().put("name", "t").put("version", "1")))
                .encode())
            .post("/mcp");
        assertEquals(401, r.statusCode());
        String challenge = r.header("WWW-Authenticate");
        assertNotNull(challenge, "WWW-Authenticate");
        assertTrue(challenge.startsWith("Bearer"), challenge);
        assertTrue(challenge.contains("resource_metadata=\""), challenge);

        Response meta = given().get("/.well-known/oauth-protected-resource");
        assertEquals(200, meta.statusCode(), meta.asString());
        JsonObject body = new JsonObject(meta.asString());
        assertTrue(body.getJsonArray("authorization_servers").contains(ForwardTestResource.base + "/realms/demo"),
                body.encode());
        assertTrue(body.getString("resource").endsWith("/mcp") || body.getString("resource").contains("localhost"),
                body.encode());
    }

    @Test
    void boundEntriesWorkWithTheCallersLogin() {
        // anonymous: the bound entry challenges like the root
        Response r = given().header("Accept", "application/json, text/event-stream")
            .header("Content-Type", "application/json")
            .body("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{}}")
            .post("/mcp/s/default/demo");
        assertEquals(401, r.statusCode());
        assertTrue(r.header("WWW-Authenticate").startsWith("Bearer"), r.header("WWW-Authenticate"));

        McpClient alice = new McpClient().path("/mcp/s/default/demo")
            .bearer(ForwardTestResource.token("mcp-consumer", "alice", "alice"))
            .initialize(false);
        JsonObject who = McpClient.text(alice.callTool("whoami", new JsonObject()));
        assertEquals("alice", who.getJsonObject("caller").getString("username"), who.encode());
        assertEquals("demo", who.getJsonObject("entry").getString("realm"), who.encode());
        JsonObject found = McpClient
            .text(alice.callTool("keycloak_user_search", new JsonObject().put("search", "carol")));
        assertEquals("carol", found.getJsonArray("items").getJsonObject(0).getString("username"), found.encode());
        JsonObject elsewhere = McpClient
            .text(alice.callTool("keycloak_user_search", new JsonObject().put("realm", "master").put("search", "x")));
        assertEquals("entry_mismatch", elsewhere.getString("error"), elsewhere.encode());
    }

    @Test
    void adminUserActsWithHerOwnToken() {
        McpClient alice = as("alice");
        assertFalse(alice.listTools().isEmpty());
        JsonObject found = McpClient
            .text(alice.callTool("keycloak_user_search", new JsonObject().put("search", "carol")));
        assertEquals("carol", found.getJsonArray("items").getJsonObject(0).getString("username"), found.encode());
        JsonObject updated = alice.callTool("keycloak_user_update",
                new JsonObject().put("id", "carol").put("lastName", "Danvers"));
        assertFalse(updated.getBoolean("isError", false), McpClient.text(updated).encode());
        assertEquals("Danvers", McpClient.text(alice.callTool("keycloak_user_get", new JsonObject().put("id", "carol")))
            .getString("lastName"));
    }

    @Test
    void viewerIsLimitedByHerOwnRoles() {
        McpClient carol = as("carol");
        JsonObject found = McpClient
            .text(carol.callTool("keycloak_user_search", new JsonObject().put("search", "alice")));
        assertEquals("alice", found.getJsonArray("items").getJsonObject(0).getString("username"), found.encode());
        JsonObject denied = carol.callTool("keycloak_user_update",
                new JsonObject().put("id", "alice").put("lastName", "X"));
        assertTrue(denied.getBoolean("isError", false));
        JsonObject body = McpClient.text(denied);
        assertEquals("forbidden", body.getString("error"), body.encode());
        assertTrue(body.getJsonArray("missingRoles").contains("manage-users"), body.encode());
        assertTrue(body.getString("message").contains("carol"), body.encode());
    }

    @Test
    void viewerIsToldUpFrontWhatSheMayDo() {
        McpClient carol = as("carol");
        JsonObject search = McpClient
            .text(carol.callTool("search_tools", new JsonObject().put("query", "disable user")));
        JsonObject disable = search.getJsonArray("tools")
            .stream()
            .map(t -> (JsonObject) t)
            .filter(t -> t.getString("name").equals("keycloak_user_set_enabled"))
            .findFirst()
            .orElseThrow();
        assertEquals(false, disable.getBoolean("allowed"), disable.encode());
        assertTrue(disable.getJsonArray("missingRoles").contains("manage-users"), disable.encode());
        assertTrue(search.getString("hint").contains("whoami"), search.encode());

        JsonObject me = McpClient.text(carol.callTool("whoami", new JsonObject().put("language", "de")));
        assertEquals("carol", me.getJsonObject("caller").getString("username"), me.encode());
        assertTrue(me.getString("keycloakCallsRunAs").contains("delegated"), me.encode());
        JsonArray roles = me.getJsonObject("roles").getJsonArray("demo");
        assertTrue(roles.stream().map(r -> ((JsonObject) r).getString("label")).toList().contains("Benutzer anzeigen"),
                me.encode());
        JsonObject can = me.getJsonObject("can").getJsonObject("demo");
        assertEquals("view", can.getString("users"), me.encode());
        assertEquals("none", can.getString("clients"), me.encode());
        assertTrue(me.getJsonObject("tools").getInteger("forbidden") > 0, me.encode());

        JsonObject alice = McpClient.text(as("alice").callTool("whoami", new JsonObject()));
        assertEquals("manage", alice.getJsonObject("can").getJsonObject("demo").getString("clients"), alice.encode());
        assertEquals(0, alice.getJsonObject("tools").getInteger("forbidden"), alice.encode());
    }

    @Test
    void userWithoutAdminRolesIsRefusedByKeycloak() {
        McpClient bob = as("bob");
        JsonObject denied = bob.callTool("keycloak_user_search", new JsonObject().put("search", "alice"));
        assertTrue(denied.getBoolean("isError", false));
        assertEquals("forbidden", McpClient.text(denied).getString("error"), McpClient.text(denied).encode());
    }

    @Test
    void tokenWithoutTheServerAudienceIsRejected() {
        String token = ForwardTestResource.token("other-app", "alice", "alice");
        IllegalStateException e = assertThrows(IllegalStateException.class,
                () -> new McpClient().bearer(token).initialize(false));
        assertTrue(e.getMessage().startsWith("HTTP 401"), e.getMessage());
    }
}
