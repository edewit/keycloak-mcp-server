package com.github.thomasdarimont.keycloak.mcp.backend.keycloak;

import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.github.thomasdarimont.keycloak.mcp.backend.McpClient;

import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import io.vertx.core.json.JsonObject;

import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@QuarkusTest
@TestProfile(DynamicSystemsProfile.class)
class DynamicSystemsEndpointTest {

    McpClient mcp;

    @BeforeEach
    void connect() {
        mcp = new McpClient().initialize(false);
    }

    @Test
    void toolsTakeAFreeTextSystemArgument() {
        JsonObject props = mcp.listTools()
            .stream()
            .map(t -> (JsonObject) t)
            .filter(t -> t.getString("name").equals("keycloak_user_search"))
            .findFirst()
            .orElseThrow()
            .getJsonObject("inputSchema")
            .getJsonObject("properties");
        JsonObject system = props.getJsonObject("system");
        assertEquals("string", system.getString("type"));
        assertFalse(system.containsKey("enum"), system.encode());
        assertTrue(system.getString("description").contains("lab"), system.encode());
    }

    @Test
    void runtimeSystemsAreReachableByName() {
        JsonObject lab = McpClient.text(mcp.callTool("keycloak_user_search",
                new JsonObject().put("system", "lab").put("realm", "tenant").put("search", "bob")));
        assertNotEquals("unknown_system", lab.getString("error"), lab.encode());
        assertEquals("keycloak_unreachable", lab.getString("error"), lab.encode());

        JsonObject nope = McpClient.text(mcp.callTool("keycloak_user_search",
                new JsonObject().put("system", "nope").put("realm", "tenant").put("search", "bob")));
        assertEquals("unknown_system", nope.getString("error"), nope.encode());
        assertEquals(List.of("default", "lab"), nope.getJsonArray("systems").getList());

        JsonObject who = McpClient.text(mcp.callTool("whoami", new JsonObject().put("system", "lab")));
        assertEquals("lab", who.getString("system"), who.encode());
    }

    @Test
    void eachPrivateKeyJwtSystemPublishesItsOwnKey() {
        String body = given().get("/auth/keys/lab/jwks.json")
            .then()
            .statusCode(200)
            .header("Cache-Control", org.hamcrest.Matchers.containsString("max-age"))
            .extract()
            .asString();
        JsonObject key = new JsonObject(body).getJsonArray("keys").getJsonObject(0);
        assertEquals("RSA", key.getString("kty"));
        assertEquals("RS256", key.getString("alg"));
        assertTrue(key.getString("kid").length() > 10, key.encode());
        // stable across requests: the key is stored, not regenerated
        assertEquals(body, given().get("/auth/keys/lab/jwks.json").then().statusCode(200).extract().asString());
        // the static default system authenticates with a password: no key
        given().get("/auth/keys/default/jwks.json").then().statusCode(404);
        given().get("/auth/keys/nope/jwks.json").then().statusCode(404);
        given().get("/.well-known/jwks.json").then().statusCode(404);
    }
}
