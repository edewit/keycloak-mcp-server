package com.github.thomasdarimont.keycloak.mcp.backend;

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
 * first never has their token sent to the second.
 */
@QuarkusTest
@QuarkusTestResource(value = TwoKeycloaksTestResource.class, restrictToAnnotatedClass = true)
class TwoKeycloaksIT {

    @Test
    void aCallerOfOneKeycloakCannotActOnTheOther() {
        McpClient alice = new McpClient().bearer(ForwardTestResource.token("mcp-consumer", "alice", "alice"))
            .initialize(false);
        JsonObject who = McpClient.text(alice.callTool("whoami", new JsonObject()));
        assertEquals("alice", who.getJsonObject("caller").getString("username"), who.encode());

        // the default system (alice's Keycloak) works as before
        JsonObject found = McpClient
            .text(alice.callTool("keycloak_user_search", new JsonObject().put("search", "carol")));
        assertEquals(null, found.getString("error"), found.encode());
        assertEquals("carol", found.getJsonArray("items").getJsonObject(0).getString("username"), found.encode());

        // naming the other system: refused before the token travels
        JsonObject foreign = McpClient.text(alice.callTool("keycloak_user_search",
                new JsonObject().put("system", "other").put("realm", "master").put("search", "x")));
        assertEquals("caller_foreign_system", foreign.getString("error"), foreign.encode());
        assertTrue(foreign.getString("message").contains("/mcp/systems/other"), foreign.encode());
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
