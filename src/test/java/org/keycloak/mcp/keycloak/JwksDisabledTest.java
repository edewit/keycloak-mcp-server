package org.keycloak.mcp.keycloak;

import static io.restassured.RestAssured.given;

import org.junit.jupiter.api.Test;

import io.quarkus.test.junit.QuarkusTest;

/** Default test profile authenticates with a password grant: no key, no JWKS. */
@QuarkusTest
class JwksDisabledTest {

    @Test
    void noJwksWithoutPrivateKeyJwt() {
        given().get("/.well-known/jwks.json").then().statusCode(404);
    }
}
