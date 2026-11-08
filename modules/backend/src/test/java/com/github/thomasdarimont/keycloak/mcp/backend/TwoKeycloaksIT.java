package com.github.thomasdarimont.keycloak.mcp.backend;

import java.util.List;

import org.junit.jupiter.api.Test;

import io.quarkus.test.common.QuarkusTestResource;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.response.Response;
import io.vertx.core.json.JsonObject;

import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Two independent Keycloaks behind one server in forward delegation: a caller of the
 * first never has their token sent to the second, a caller of the second administers it
 * through its entry.
 */
@QuarkusTest
@QuarkusTestResource(value = TwoKeycloaksTestResource.class, restrictToAnnotatedClass = true)
class TwoKeycloaksIT {

    @Test
    void aCallerOfOneKeycloakCannotActOnTheOther() {
        String aliceToken = ForwardTestResource.token("mcp-consumer", "alice", "alice");

        // her own Keycloak, through its entry: works as before
        McpClient own = new McpClient().path("/mcp/systems/default").bearer(aliceToken).initialize(false);
        JsonObject found = McpClient
            .text(own.callTool("keycloak_user_search", new JsonObject().put("search", "carol")));
        assertEquals(null, found.getString("error"), found.encode());
        assertTrue(usernames(found).contains("carol"), found.encode());

        // the root entry: the default tenant verified her token (first Keycloak), the
        // default system is the second;
        // that the tenant trusts her issuer does not make it the second system's issuer
        McpClient root = new McpClient().bearer(aliceToken).initialize(false);
        JsonObject who = McpClient.text(root.callTool("whoami", new JsonObject()));
        assertEquals("alice", who.getJsonObject("caller").getString("username"), who.encode());
        JsonObject implicit = McpClient
            .text(root.callTool("keycloak_user_search", new JsonObject().put("realm", "master").put("search", "x")));
        assertEquals("caller_foreign_system", implicit.getString("error"), implicit.encode());
        JsonObject named = McpClient.text(root.callTool("keycloak_user_search",
                new JsonObject().put("system", "other").put("realm", "master").put("search", "x")));
        assertEquals("caller_foreign_system", named.getString("error"), named.encode());
        assertTrue(named.getString("message").contains("/mcp/systems/other"), named.encode());
    }

    @Test
    void aCallerOfTheOtherKeycloakAdministersItThroughItsEntry() {
        String adminToken = TwoKeycloaksTestResource.otherToken("mcp-consumer", "admin", "admin");

        McpClient other = new McpClient().path("/mcp/systems/other").bearer(adminToken).initialize(false);
        JsonObject who = McpClient.text(other.callTool("whoami", new JsonObject()));
        assertEquals("admin", who.getJsonObject("caller").getString("username"), who.encode());
        // the token of the second Keycloak is forwarded to it: the search runs with the
        // caller's rights there
        JsonObject found = McpClient
            .text(other.callTool("keycloak_user_search", new JsonObject().put("search", "admin")));
        assertEquals(null, found.getString("error"), found.encode());
        assertTrue(usernames(found).contains("admin"), found.encode());
        // the first Keycloak's realm is not his to reach: the bound entry refuses the
        // system argument before the issuer is even looked at
        JsonObject foreign = McpClient.text(other.callTool("keycloak_user_search",
                new JsonObject().put("system", "default").put("realm", "demo").put("search", "alice")));
        assertEquals("entry_mismatch", foreign.getString("error"), foreign.encode());

        // and the first system's entry does not accept his token either
        Response r = given().header("Accept", "application/json, text/event-stream")
            .header("Content-Type", "application/json")
            .header("Authorization", "Bearer " + adminToken)
            .body("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{}}")
            .post("/mcp/systems/default");
        assertEquals(401, r.statusCode(), r.asString());
    }

    private static List<String> usernames(JsonObject searchResult) {
        return searchResult.getJsonArray("items")
            .stream()
            .map(item -> ((JsonObject) item).getString("username"))
            .toList();
    }

    @Test
    void theOtherSystemsEntryDoesNotAcceptTheFirstKeycloaksTokens() {
        Response r = given().header("Accept", "application/json, text/event-stream")
            .header("Content-Type", "application/json")
            .header("Authorization", "Bearer " + ForwardTestResource.token("mcp-consumer", "alice", "alice"))
            .body("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{}}")
            .post("/mcp/systems/other");
        assertEquals(401, r.statusCode(), r.asString());
    }
}
