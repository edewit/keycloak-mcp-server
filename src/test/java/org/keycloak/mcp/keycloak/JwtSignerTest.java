package org.keycloak.mcp.keycloak;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;

import org.junit.jupiter.api.Test;

import io.vertx.core.json.JsonObject;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JwtSignerTest {

    @Test
    void rs256RoundTrip() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        KeyPair kp = gen.generateKeyPair();
        JwtSigner signer = new JwtSigner(kp.getPrivate(), "RS256", "key-1");
        String jwt = signer.sign(new JsonObject().put("iss", "c").put("sub", "c"));
        String[] parts = jwt.split("\\.");
        assertEquals(3, parts.length);
        JsonObject header = new JsonObject(new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8));
        assertEquals("RS256", header.getString("alg"));
        assertEquals("key-1", header.getString("kid"));
        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(kp.getPublic());
        verifier.update((parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII));
        assertTrue(verifier.verify(Base64.getUrlDecoder().decode(parts[2])));
    }

    @Test
    void es256ProducesJoseSignature() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
        gen.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair kp = gen.generateKeyPair();
        String jwt = new JwtSigner(kp.getPrivate(), "ES256", null).sign(new JsonObject().put("a", 1));
        byte[] sig = Base64.getUrlDecoder().decode(jwt.split("\\.")[2]);
        assertEquals(64, sig.length);
    }

    @Test
    void pemParsing() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        KeyPair kp = gen.generateKeyPair();
        String pem = "-----BEGIN PRIVATE KEY-----\n"
                + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(kp.getPrivate().getEncoded())
                + "\n-----END PRIVATE KEY-----\n";
        assertEquals(kp.getPrivate(), JwtSigner.parsePem(pem));
        assertThrows(Exception.class,
                () -> JwtSigner.parsePem("-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----"));
    }

    @Test
    void tokenEndpointKeepsContextPath() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        JwtSigner signer = new JwtSigner(gen.generateKeyPair().getPrivate(), "RS256", null);
        for (String base : new String[] { "https://sso.example.com/auth", "https://sso.example.com/auth/" }) {
            ClientAssertionTokenManager tm = new ClientAssertionTokenManager(null, base, "master", "c", signer, 60,
                    org.keycloak.mcp.config.GrantType.CLIENT_CREDENTIALS, null, null);
            assertEquals("https://sso.example.com/auth/realms/master/protocol/openid-connect/token",
                    tm.tokenEndpoint());
            assertEquals("https://sso.example.com/auth/realms/master", tm.audience());
        }
    }

    @Test
    void keyTypeMustMatchAlgorithm() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        KeyPair kp = gen.generateKeyPair();
        assertThrows(IllegalStateException.class, () -> new JwtSigner(kp.getPrivate(), "ES256", null));
    }
}
