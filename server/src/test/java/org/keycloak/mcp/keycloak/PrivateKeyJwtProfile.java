package org.keycloak.mcp.keycloak;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;
import java.util.Map;

import io.quarkus.test.junit.QuarkusTestProfile;

/**
 * Server configured for private_key_jwt with a freshly generated RSA key written to a
 * temp PEM file.
 */
public class PrivateKeyJwtProfile implements QuarkusTestProfile {

    public static KeyPair keyPair;
    public static Path pem;

    @Override
    public Map<String, String> getConfigOverrides() {
        try {
            KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
            gen.initialize(2048);
            keyPair = gen.generateKeyPair();
            pem = Files.createTempFile("kc-mcp-test", ".pem");
            Files
                .writeString(pem,
                        "-----BEGIN PRIVATE KEY-----\n"
                                + Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII))
                                    .encodeToString(keyPair.getPrivate().getEncoded())
                                + "\n-----END PRIVATE KEY-----\n");
        }
        catch (IOException | java.security.GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
        return Map.of("kc-mcp.grant-type", "client_credentials", "kc-mcp.client-auth", "private_key_jwt",
                "kc-mcp.client-id", "mcp-admin", "kc-mcp.jwt.key-file", pem.toString(), "kc-mcp.jwt.key-id",
                "kc-mcp-test-key", "kc-mcp.startup-check", "off");
    }
}
