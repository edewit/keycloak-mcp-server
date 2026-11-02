package org.keycloak.mcp.keycloak;

import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.math.BigInteger;
import java.nio.file.Path;
import java.security.interfaces.RSAPrivateCrtKey;
import java.util.Base64;

import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.junit.jupiter.api.Test;

import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import io.vertx.core.json.JsonObject;

@QuarkusTest
@TestProfile(PrivateKeyJwtProfile.class)
class JwksEndpointTest {

    @ConfigProperty(name = "kc-mcp.jwt.key-file")
    String keyFile;

    @Test
    void servesTheConfiguredPublicKey() throws Exception {
        String body = given().get("/.well-known/jwks.json")
                .then().statusCode(200)
                .header("Content-Type", org.hamcrest.Matchers.containsString("application/json"))
                .header("Cache-Control", org.hamcrest.Matchers.containsString("max-age"))
                .extract().asString();
        JsonObject key = new JsonObject(body).getJsonArray("keys").getJsonObject(0);
        assertEquals("RSA", key.getString("kty"));
        assertEquals("RS256", key.getString("alg"));
        assertEquals("kc-mcp-test-key", key.getString("kid"));
        BigInteger n = new BigInteger(1, Base64.getUrlDecoder().decode(key.getString("n")));
        // compare with the key the application loaded (the profile may be instantiated per class loader)
        RSAPrivateCrtKey loaded = (RSAPrivateCrtKey) JwtSigner.loadPem(Path.of(keyFile));
        assertEquals(loaded.getModulus(), n);
    }
}
