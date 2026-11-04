package org.keycloak.mcp.keycloak;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import io.vertx.core.json.JsonObject;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JwksTest {

    static KeyPair rsa() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        return gen.generateKeyPair();
    }

    @Test
    void rsaJwkAndThumbprint() throws Exception {
        KeyPair kp = rsa();
        JsonObject jwk = Jwks.jwk(kp.getPublic(), "RS256", null);
        assertEquals("RSA", jwk.getString("kty"));
        assertEquals("sig", jwk.getString("use"));
        assertEquals("RS256", jwk.getString("alg"));
        assertEquals("AQAB", jwk.getString("e"));
        byte[] n = Base64.getUrlDecoder().decode(jwk.getString("n"));
        assertEquals(256, n.length, "modulus without sign byte");
        assertEquals(((RSAPublicKey) kp.getPublic()).getModulus(), new java.math.BigInteger(1, n));
        assertEquals(Jwks.thumbprint(jwk), jwk.getString("kid"));
        assertEquals(43, jwk.getString("kid").length(), "base64url sha-256");
        assertEquals("my-kid", Jwks.jwk(kp.getPublic(), "RS256", "my-kid").getString("kid"));
        // thumbprint ignores alg/kid/use
        assertEquals(jwk.getString("kid"), Jwks.thumbprint(Jwks.jwk(kp.getPublic(), "PS256", "other")));
    }

    @Test
    void publicKeyDerivedFromRsaPrivateKey() throws Exception {
        KeyPair kp = rsa();
        assertEquals(kp.getPublic(), Jwks.publicKeyOf(kp.getPrivate()));
    }

    @ParameterizedTest
    @CsvSource({ "secp256r1,P-256,32", "secp384r1,P-384,48", "secp521r1,P-521,66" })
    void publicKeyDerivedFromEcPrivateKey(String curve, String crv, int len) throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
        gen.initialize(new ECGenParameterSpec(curve));
        for (int i = 0; i < 3; i++) {
            KeyPair kp = gen.generateKeyPair();
            ECPublicKey derived = Jwks.deriveEcPublic((ECPrivateKey) kp.getPrivate());
            assertEquals(((ECPublicKey) kp.getPublic()).getW(), derived.getW());
            JsonObject jwk = Jwks.jwk(derived, null, null);
            assertEquals("EC", jwk.getString("kty"));
            assertEquals(crv, jwk.getString("crv"));
            assertEquals(len, Base64.getUrlDecoder().decode(jwk.getString("x")).length);
            assertEquals(len, Base64.getUrlDecoder().decode(jwk.getString("y")).length);
        }
    }

    @Test
    void signerKidMatchesServedJwk() throws Exception {
        KeyPair kp = rsa();
        JwtSigner signer = new JwtSigner(kp.getPrivate(), "RS256", null);
        String jwt = signer.sign(new JsonObject().put("iss", "c"));
        JsonObject header = new JsonObject(
                new String(Base64.getUrlDecoder().decode(jwt.split("\\.")[0]), StandardCharsets.UTF_8));
        assertEquals(signer.jwk().getString("kid"), header.getString("kid"));
        assertEquals(Jwks.thumbprint(Jwks.jwk(kp.getPublic(), null, null)), header.getString("kid"));
        assertTrue(signer.publicKey().equals(kp.getPublic()));
    }
}
