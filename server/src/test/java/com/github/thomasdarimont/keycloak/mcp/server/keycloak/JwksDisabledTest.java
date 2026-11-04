package com.github.thomasdarimont.keycloak.mcp.server.keycloak;

import org.junit.jupiter.api.Test;

import io.quarkus.test.junit.QuarkusTest;

import static io.restassured.RestAssured.given;

/** Default test profile authenticates with a password grant: no key, no JWKS. */
@QuarkusTest
class JwksDisabledTest {

    @Test
    void noJwksWithoutPrivateKeyJwt() {
        given().get("/.well-known/jwks.json").then().statusCode(404);
    }
}
