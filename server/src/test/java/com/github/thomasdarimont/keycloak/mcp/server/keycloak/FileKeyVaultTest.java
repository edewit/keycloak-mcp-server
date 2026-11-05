package com.github.thomasdarimont.keycloak.mcp.server.keycloak;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.interfaces.RSAPublicKey;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.github.thomasdarimont.keycloak.mcp.keycloak.SigningKey;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FileKeyVaultTest {

    @Test
    void createsStoresAndReloadsOneKeyPerSystem(@TempDir Path dir) throws Exception {
        FileKeyVault vault = new FileKeyVault(dir.resolve("keys"), "RS256");
        assertTrue(vault.find("tenant-a").isEmpty());

        SigningKey a = vault.keyFor("tenant-a");
        SigningKey b = vault.keyFor("Tenant/B");
        assertTrue(Files.isRegularFile(dir.resolve("keys/tenant-a.pem")));
        assertTrue(Files.isRegularFile(dir.resolve("keys/tenant_b.pem")), "file name made safe");
        assertEquals("RS256", a.algorithm());
        assertEquals(2048, ((RSAPublicKey) a.publicKey()).getModulus().bitLength());
        assertNotEquals(((RSAPublicKey) a.publicKey()).getModulus(), ((RSAPublicKey) b.publicKey()).getModulus());
        assertTrue(vault.find("tenant-a").isPresent());

        FileKeyVault reloaded = new FileKeyVault(dir.resolve("keys"), "RS256");
        assertEquals(((RSAPublicKey) a.publicKey()).getModulus(),
                ((RSAPublicKey) reloaded.keyFor("tenant-a").publicKey()).getModulus(), "same key after a restart");
        assertEquals("file-key-vault", vault.id());
    }
}
