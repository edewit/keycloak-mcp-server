package com.github.thomasdarimont.keycloak.mcp.backend.keycloak;

import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.github.thomasdarimont.keycloak.mcp.keycloak.DefaultSigningKeyGenerator;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeyVault;
import com.github.thomasdarimont.keycloak.mcp.keycloak.SigningKey;
import com.github.thomasdarimont.keycloak.mcp.keycloak.SigningKeyGenerator;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** A vault that only serves what operations provisioned, as a secrets manager would. */
class ReadOnlyKeyVaultTest {

    static SigningKey key() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        KeyPair pair = gen.generateKeyPair();
        return new SigningKey(pair.getPrivate(), pair.getPublic(), "RS256", "ops-key-1");
    }

    @Test
    void readOnlyVaultsServeProvisionedKeysAndRefuseToCreate(@TempDir Path dir) throws Exception {
        SigningKey provisioned = key();
        KeyVault readOnly = new KeyVault() {
            final Map<String, SigningKey> keys = Map.of("tenant-a", provisioned);

            @Override
            public String id() {
                return "ops-vault";
            }

            @Override
            public Optional<SigningKey> findSigningKey(String system) {
                return Optional.ofNullable(keys.get(system));
            }

            @Override
            public Optional<String> findSecret(String name) {
                return "tenant-a/client-secret".equals(name) ? Optional.of("from-ops") : Optional.empty();
            }
        };
        assertFalse(readOnly.supportsKeyCreation());
        UnsupportedOperationException e = assertThrows(UnsupportedOperationException.class,
                () -> readOnly.createSigningKey("tenant-b"));
        assertTrue(e.getMessage().contains("ops-vault") && e.getMessage().contains("tenant-b"), e.getMessage());
        assertEquals("from-ops", readOnly.findSecret("tenant-a/client-secret").orElseThrow());

        // the server uses the provisioned key and never tries to create one
        assertSame(provisioned, SigningKeys.resolve(readOnly, "tenant-a").orElseThrow());
        assertTrue(SigningKeys.resolve(readOnly, "tenant-b").isEmpty(), "no key, no creation");

        // the built-in file vault is read-only as well
        FileKeyVault file = new FileKeyVault(dir, "RS256");
        assertFalse(file.supportsKeyCreation());
        assertTrue(SigningKeys.resolve(file, "tenant-b").isEmpty(), "no file, no key, no creation");

        // a vault that can create (a database-backed one) is asked on first use, with the
        // server's generator
        KeyVault creating = new KeyVault() {
            final Map<String, SigningKey> keys = new HashMap<>();
            SigningKeyGenerator generator;

            @Override
            public String id() {
                return "db-vault";
            }

            @Override
            public boolean supportsKeyCreation() {
                return true;
            }

            @Override
            public void useSigningKeyGenerator(SigningKeyGenerator g) {
                generator = g;
            }

            @Override
            public SigningKey createSigningKey(String system) {
                SigningKey k = generator.generate("ES256");
                keys.put(system, k);
                return k;
            }

            @Override
            public Optional<SigningKey> findSigningKey(String system) {
                return Optional.ofNullable(keys.get(system));
            }
        };
        creating.useSigningKeyGenerator(new DefaultSigningKeyGenerator());
        SigningKey made = SigningKeys.resolve(creating, "tenant-b").orElseThrow();
        assertEquals("ES256", made.algorithm());
        assertSame(made, SigningKeys.resolve(creating, "tenant-b").orElseThrow(), "found afterwards, not recreated");
    }
}
