package org.keycloak.mcp;

import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import io.quarkus.test.junit.QuarkusTest;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * End-to-end over streamable HTTP, without a Keycloak: listing, search, dispatch,
 * validation and the error shapes.
 */
@QuarkusTest
class McpEndpointTest {

    McpClient mcp;

    @BeforeEach
    void connect() {
        mcp = new McpClient().initialize(false);
    }

    @Test
    void corsAllowsLocalOriginsOnly() {
        io.restassured.RestAssured.given()
            .header("Origin", "http://localhost:5173")
            .header("Access-Control-Request-Method", "POST")
            .header("Access-Control-Request-Headers", "content-type,mcp-session-id,mcp-protocol-version")
            .options("/mcp")
            .then()
            .header("Access-Control-Allow-Origin", "http://localhost:5173")
            .header("Access-Control-Allow-Headers", org.hamcrest.Matchers.containsStringIgnoringCase("mcp-session-id"));
        io.restassured.RestAssured.given()
            .header("Origin", "https://evil.example")
            .header("Access-Control-Request-Method", "POST")
            .options("/mcp")
            .then()
            .header("Access-Control-Allow-Origin", org.hamcrest.Matchers.nullValue());
    }

    @Test
    void hybridModeListsMetaAndHotToolsOnly() {
        JsonArray tools = mcp.request("tools/list", new JsonObject()).getJsonObject("result").getJsonArray("tools");
        List<String> names = tools.stream().map(t -> ((JsonObject) t).getString("name")).sorted().toList();
        assertEquals(List.of("execute_tool", "keycloak_realm_get_config", "keycloak_server_info", "keycloak_user_get",
                "keycloak_user_search", "search_tools", "whoami"), names);
        JsonObject search = tools.stream()
            .map(t -> (JsonObject) t)
            .filter(t -> t.getString("name").equals("keycloak_user_search"))
            .findFirst()
            .orElseThrow();
        assertEquals("realm",
                search.getJsonObject("inputSchema").getJsonObject("properties").fieldNames().iterator().next());
        assertTrue(search.getJsonObject("annotations").getBoolean("readOnlyHint"));
    }

    @Test
    void searchToolsFindsExtensionAndBuiltins() {
        JsonObject r = McpClient.text(mcp.callTool("search_tools", new JsonObject().put("query", "disable user bob")));
        assertEquals("keycloak_user_set_enabled", r.getJsonArray("tools").getJsonObject(0).getString("name"));
        JsonObject acme = McpClient.text(mcp.callTool("search_tools", new JsonObject().put("query", "acme ping")));
        assertEquals("keycloak_acme_ping", acme.getJsonArray("tools").getJsonObject(0).getString("name"));
        JsonObject cats = McpClient.text(mcp.callTool("search_tools", new JsonObject()));
        assertTrue(cats.getJsonArray("categories").size() >= 5);
    }

    @Test
    void executeToolDispatchesToExtensionWithProviderConfig() {
        JsonObject result = mcp.callTool("execute_tool",
                new JsonObject().put("name", "acme_ping").put("arguments", new JsonObject().put("name", "Tom")));
        assertFalse(result.getBoolean("isError", false));
        JsonObject r = McpClient.text(result);
        assertEquals("hello from config", r.getString("greeting"));
        assertEquals("Tom", r.getString("name"));
    }

    @Test
    void callerIsResolvedPerRequest() {
        assertEquals("anonymous",
                McpClient.text(mcp.callTool("keycloak_acme_ping", new JsonObject())).getString("caller"));
        JsonObject meta = new JsonObject().put("kc-mcp/test-caller", "alice");
        assertEquals("alice",
                McpClient.text(mcp.callTool("keycloak_acme_ping", new JsonObject(), meta)).getString("caller"));
    }

    @Test
    void providerAccessChecksApply() {
        JsonObject result = mcp.callTool("keycloak_acme_ping", new JsonObject().put("name", "mallory"));
        assertTrue(result.getBoolean("isError"));
        assertEquals("blocked_name", McpClient.text(result).getString("error"));
    }

    @Test
    void serviceLoaderAccessChecksApply() {
        JsonObject result = mcp.callTool("keycloak_acme_ping", new JsonObject().put("name", "standalone"));
        assertTrue(result.getBoolean("isError"));
        assertEquals("standalone_denied", McpClient.text(result).getString("error"));
    }

    @Test
    void hiddenToolsAreStillCallableDirectly() {
        JsonObject result = mcp.callTool("keycloak_acme_ping", new JsonObject());
        assertEquals("world", McpClient.text(result).getString("name"));
    }

    @Test
    void keycloakDownYieldsStructuredError() {
        JsonObject result = mcp.callTool("keycloak_user_search", new JsonObject().put("realm", "demo"));
        assertTrue(result.getBoolean("isError"));
        assertEquals("keycloak_unreachable", McpClient.text(result).getString("error"));
    }

    @Test
    void validationErrorsViaExecuteTool() {
        JsonObject result = mcp.callTool("execute_tool", new JsonObject().put("name", "keycloak_user_set_enabled")
            .put("arguments", new JsonObject().put("realm", "demo")));
        assertTrue(result.getBoolean("isError"));
        JsonObject r = McpClient.text(result);
        assertEquals("invalid_arguments", r.getString("error"));
        assertNotNull(r.getJsonObject("inputSchema"));
        JsonObject unknown = McpClient.text(mcp.callTool("execute_tool",
                new JsonObject().put("name", "keycloak_user_serach").put("arguments", new JsonObject())));
        assertEquals("unknown_tool", unknown.getString("error"));
        assertEquals("keycloak_user_search", unknown.getJsonArray("didYouMean").getJsonObject(0).getString("name"));
    }

    @Test
    void destructiveWithoutElicitationNeedsConfirmFlag() {
        JsonObject args = new JsonObject().put("realm", "demo").put("id", "x");
        JsonObject r = McpClient.text(mcp.callTool("keycloak_user_logout", args));
        assertEquals("confirmation_required", r.getString("error"));
        // with confirm the guard passes and we reach Keycloak (which is down)
        JsonObject r2 = McpClient.text(mcp.callTool("keycloak_user_logout", args.copy().put("confirm", true)));
        assertEquals("keycloak_unreachable", r2.getString("error"));
    }
}
