package com.github.thomasdarimont.keycloak.mcp.backend.admin;

import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import com.github.thomasdarimont.keycloak.mcp.backend.McpClient;

import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import io.restassured.specification.RequestSpecification;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.hasKey;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Registering a system through the admin API: stored in the database, its key created in
 * the vault, its JWKS served, its entries reachable, and gone again on DELETE.
 */
@QuarkusTest
@TestProfile(AdminProfile.class)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class AdminResourceTest {

    static RequestSpecification admin() {
        return given().header("Authorization", "Bearer " + AdminProfile.TOKEN).contentType("application/json");
    }

    @Test
    @Order(1)
    void theAdminApiNeedsTheToken() {
        given().get("/admin/systems").then().statusCode(401).header("WWW-Authenticate", containsString("Bearer"));
        given().header("Authorization", "Bearer nope").get("/admin/systems").then().statusCode(401);
        admin().get("/admin/systems").then().statusCode(200).body("systems.alias", hasItem("default"));
    }

    @Test
    @Order(2)
    void registersASystemWithAGeneratedKeyAndServesItsJwks() {
        JsonObject body = new JsonObject().put("displayName", "ACME Corp.")
            .put("url", "http://127.0.0.1:1")
            .put("issuer", "https://sso.example.com/realms/master")
            .put("defaultRealm", "acme-dev")
            .put("allowedRealms", new JsonArray().add("acme-dev").add("acme-prod"))
            .put("version", "26.8.1");
        String response = admin().body(body.encode())
            .put("/admin/systems/acme")
            .then()
            .statusCode(201)
            .body("alias", equalTo("acme"))
            .body("displayName", equalTo("ACME Corp."))
            .body("clientAuth", equalTo("private_key_jwt"))
            .body("clientId", equalTo("keycloak-mcp-server"))
            .body("source", equalTo("db-systems"))
            .body("signingKey.vault", equalTo("db-key-vault"))
            .body("signingKey.algorithm", equalTo("RS256"))
            .body("signingKey.jwksPath", equalTo("/auth/keys/acme/jwks.json"))
            .body("signingKey.jwksUrl", startsWith("http://localhost:"))
            .body("signingKey.jwksUrl", containsString("/auth/keys/acme/jwks.json"))
            .body("entries", hasItem("/mcp/s/acme"))
            .body("entries", hasItem("/mcp/s/acme/acme-dev"))
            .body("entries", hasItem("/mcp/s/acme/acme-prod"))
            .body("$", not(hasKey("clientSecret")))
            .extract()
            .asString();
        String kid = new JsonObject(response).getJsonObject("signingKey").getString("kid");
        assertTrue(kid != null && kid.length() > 10, response);

        // the JWKS Keycloak fetches carries that key
        given().get("/auth/keys/acme/jwks.json")
            .then()
            .statusCode(200)
            .body("keys[0].kid", equalTo(kid))
            .body("keys[0].kty", equalTo("RSA"));

        // the system is live: its entry answers
        JsonObject who = McpClient
            .text(new McpClient().path("/mcp/s/acme").initialize(false).callTool("whoami", new JsonObject()));
        assertEquals("acme", who.getString("system"), who.encode());

        // and visible in the listing and alone
        admin().get("/admin/systems").then().statusCode(200).body("systems.alias", hasItem("acme"));
        admin().get("/admin/systems/acme").then().statusCode(200).body("defaultRealm", equalTo("acme-dev"));

        // a second registration with generate is refused, a plain replace keeps the key
        admin().body(body.copy().put("signingKey", "generate").encode())
            .put("/admin/systems/acme")
            .then()
            .statusCode(409)
            .body("error", equalTo("signing_key_exists"));
        admin().body(body.copy().put("displayName", "ACME Inc.").encode())
            .put("/admin/systems/acme")
            .then()
            .statusCode(200)
            .body("displayName", equalTo("ACME Inc."))
            .body("signingKey.kid", equalTo(kid));

        // rotation: new kid, new JWKS
        String rotated = admin().post("/admin/systems/acme/signing-key")
            .then()
            .statusCode(200)
            .extract()
            .path("signingKey.kid");
        assertNotEquals(kid, rotated);
        given().get("/auth/keys/acme/jwks.json").then().statusCode(200).body("keys[0].kid", equalTo(rotated));
    }

    @Test
    @Order(3)
    void refusesWhatItCannotRegister() {
        admin().body("{\"displayName\": \"no url\"}")
            .put("/admin/systems/broken")
            .then()
            .statusCode(400)
            .body("error", equalTo("invalid_system"));
        admin().body("not json").put("/admin/systems/broken").then().statusCode(400);
        admin().body("{\"url\": \"http://127.0.0.1:1\"}")
            .put("/admin/systems/bad alias")
            .then()
            .statusCode(400)
            .body("error", equalTo("invalid_alias"));
        admin().body("{\"url\": \"http://kc.evil.test\"}")
            .put("/admin/systems/evil")
            .then()
            .statusCode(400)
            .body("error", equalTo("host_not_allowed"));
        admin().body("{\"url\": \"http://127.0.0.1:1\", \"signingKey\": \"existing\"}")
            .put("/admin/systems/no-key")
            .then()
            .statusCode(400)
            .body("error", equalTo("no_signing_key"));
        admin()
            .body("{\"url\": \"http://127.0.0.1:1\", \"clientAuth\": \"client_secret\","
                    + " \"clientSecret\": \"vault:acme/client-secret\"}")
            .put("/admin/systems/by-secret")
            .then()
            .statusCode(400)
            .body("error", equalTo("unknown_secret"));
        // the static configuration is not the admin API's to change
        admin().body("{\"url\": \"http://127.0.0.1:1\"}")
            .put("/admin/systems/default")
            .then()
            .statusCode(409)
            .body("error", equalTo("system_configured"));
        admin().delete("/admin/systems/default").then().statusCode(409);
        admin().delete("/admin/systems/nope").then().statusCode(404);
        admin().post("/admin/systems/nope/signing-key").then().statusCode(404);
    }

    @Test
    @Order(4)
    void deleteRemovesTheSystem() {
        admin().delete("/admin/systems/acme").then().statusCode(204);
        admin().get("/admin/systems/acme").then().statusCode(404);
        given().get("/auth/keys/acme/jwks.json").then().statusCode(404);
        admin().get("/admin/systems").then().statusCode(200).body("systems.alias", not(hasItem("acme")));
    }
}
