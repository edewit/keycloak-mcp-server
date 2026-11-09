package com.github.thomasdarimont.keycloak.mcp.backend.keycloak;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.github.thomasdarimont.keycloak.mcp.keycloak.SigningKey;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FileKeyVaultTest {

    @Test
    void servesProvisionedPemFilesAndSecretsAndNeverWrites(@TempDir Path dir) throws Exception {
        Path keys = dir.resolve("keys");
        FileKeyVault vault = new FileKeyVault(keys, "RS256");
        assertTrue(vault.findSigningKey("tenant-a").isEmpty(), "nothing provisioned yet");
        assertFalse(vault.supportsKeyCreation());
        assertThrows(UnsupportedOperationException.class, () -> vault.createSigningKey("tenant-a"));
        assertFalse(Files.exists(keys), "a read-only vault creates nothing, not even its directory");

        // operations drop PEM files in; the name is made file-safe
        KeyPair a = TestKeys.rsa();
        TestKeys.writePem(keys.resolve("tenant-a.pem"), a.getPrivate());
        TestKeys.writePem(keys.resolve("tenant_b.pem"), TestKeys.rsa().getPrivate());
        SigningKey loaded = vault.findSigningKey("tenant-a").orElseThrow();
        assertEquals(((RSAPublicKey) a.getPublic()).getModulus(), ((RSAPublicKey) loaded.publicKey()).getModulus(),
                "public key derived from the provisioned private key");
        assertEquals("RS256", loaded.algorithm());
        assertTrue(vault.findSigningKey("Tenant/B").isPresent(), "Tenant/B -> tenant_b.pem");
        assertEquals("file", vault.id());

        // raw secrets: files under <dir>/secrets, by file-safe name
        assertTrue(vault.findSecret("tenant-a/client-secret").isEmpty());
        Files.createDirectories(keys.resolve("secrets"));
        Files.writeString(keys.resolve("secrets/tenant-a_client-secret"), "s3cr3t\n");
        assertEquals("s3cr3t", vault.findSecret("tenant-a/client-secret").orElseThrow());
        Files.writeString(keys.resolve("secrets/blank"), "  \n");
        assertTrue(vault.findSecret("blank").isEmpty(), "a blank file is no secret");
    }
}
