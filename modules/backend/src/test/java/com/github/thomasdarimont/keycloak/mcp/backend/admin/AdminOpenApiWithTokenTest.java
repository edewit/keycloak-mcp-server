package com.github.thomasdarimont.keycloak.mcp.backend.admin;

import java.util.Set;

import org.junit.jupiter.api.Test;

import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import io.vertx.core.json.JsonObject;

import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** With the admin API on and a static token, the document offers exactly that way in. */
@QuarkusTest
@TestProfile(AdminProfile.class)
class AdminOpenApiWithTokenTest {

    @Test
    void theStaticTokenIsTheOnlyAuthorization() {
        JsonObject doc = new JsonObject(given().get("/q/openapi?format=json").asString());
        JsonObject schemes = doc.getJsonObject("components").getJsonObject("securitySchemes");
        assertEquals(Set.of(AdminOpenApiFilter.TOKEN), schemes.fieldNames());
        assertEquals("bearer", schemes.getJsonObject(AdminOpenApiFilter.TOKEN).getString("scheme"));
        assertEquals(1, doc.getJsonArray("security").size());
        assertTrue(doc.getJsonArray("security").getJsonObject(0).containsKey(AdminOpenApiFilter.TOKEN));
        assertFalse(doc.getJsonObject("info").getString("description").contains("is off"));
    }
}
