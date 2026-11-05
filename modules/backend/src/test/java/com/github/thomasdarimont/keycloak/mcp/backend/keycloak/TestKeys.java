package com.github.thomasdarimont.keycloak.mcp.backend.keycloak;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;

/** Keys the tests provision the way operations would: PKCS#8 PEM files. */
final class TestKeys {

    private TestKeys() {
    }

    static KeyPair rsa() {
        try {
            KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
            gen.initialize(2048);
            return gen.generateKeyPair();
        }
        catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    static KeyPair ec(String curve) {
        try {
            KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
            gen.initialize(new ECGenParameterSpec(curve));
            return gen.generateKeyPair();
        }
        catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Writes the key as {@code BEGIN PRIVATE KEY} PEM, creating parent directories. */
    static Path writePem(Path file, PrivateKey key) {
        try {
            Files.createDirectories(file.getParent());
            Files.writeString(file,
                    "-----BEGIN PRIVATE KEY-----\n"
                            + Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII))
                                .encodeToString(key.getEncoded())
                            + "\n-----END PRIVATE KEY-----\n",
                    StandardCharsets.US_ASCII);
            return file;
        }
        catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }
}
