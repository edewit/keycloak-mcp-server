package com.github.thomasdarimont.keycloak.mcp.backend.keycloak;

import java.nio.file.Path;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.github.thomasdarimont.keycloak.mcp.keycloak.DefaultSigningKeyGenerator;
import com.github.thomasdarimont.keycloak.mcp.keycloak.SigningKey;

import io.vertx.core.json.JsonObject;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SigningKeyGeneratorTest {

    @Test
    void generatesTheKeyKindTheAlgorithmNeeds() {
        DefaultSigningKeyGenerator gen = new DefaultSigningKeyGenerator(3072);
        assertTrue(gen.supports("RS256") && gen.supports("ps384") && gen.supports("ES512"));
        assertFalse(gen.supports("HS256"));
        assertFalse(gen.supports("EdDSA"));
        assertEquals(3072, ((RSAPublicKey) gen.generate("RS256").publicKey()).getModulus().bitLength());
        assertEquals("PS512", gen.generate("ps512").algorithm());
        SigningKey es256 = gen.generate("ES256");
        assertEquals(256, ((ECPublicKey) es256.publicKey()).getParams().getCurve().getField().getFieldSize());
        assertEquals(384,
                ((ECPublicKey) gen.generate("ES384").publicKey()).getParams().getCurve().getField().getFieldSize());
        assertEquals(521,
                ((ECPublicKey) gen.generate("ES512").publicKey()).getParams().getCurve().getField().getFieldSize());
        assertThrows(IllegalArgumentException.class, () -> gen.generate("HS256"));
        assertThrows(IllegalArgumentException.class, () -> new DefaultSigningKeyGenerator(1024));
    }

    @Test
    void provisionedEcKeysLoadFromTheFileVaultAndSign(@TempDir Path dir) throws Exception {
        SigningKey created = new DefaultSigningKeyGenerator().generate("ES256");
        TestKeys.writePem(dir.resolve("tenant-ec.pem"), created.privateKey());
        SigningKey reloaded = new FileKeyVault(dir, "ES256").findSigningKey("tenant-ec").orElseThrow();
        assertEquals(((ECPublicKey) created.publicKey()).getW(), ((ECPublicKey) reloaded.publicKey()).getW(),
                "the EC public key is derived again from the stored PKCS#8 file");

        JwtSigner signer = new JwtSigner(reloaded.privateKey(), reloaded.publicKey(), "ES256", null);
        assertEquals("EC", signer.jwk().getString("kty"));
        assertEquals("P-256", signer.jwk().getString("crv"));
        String jws = signer.sign(new JsonObject().put("sub", "x"));
        JsonObject header = new JsonObject(new String(Base64.getUrlDecoder().decode(jws.split("\\.")[0])));
        assertEquals("ES256", header.getString("alg"));
        assertEquals(signer.keyId(), header.getString("kid"));

    }
}
