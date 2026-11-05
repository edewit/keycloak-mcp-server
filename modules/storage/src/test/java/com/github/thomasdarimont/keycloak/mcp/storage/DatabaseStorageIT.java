package com.github.thomasdarimont.keycloak.mcp.storage;

import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import jakarta.enterprise.inject.Any;
import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;

import org.junit.jupiter.api.Test;

import com.github.thomasdarimont.keycloak.mcp.access.Caller;
import com.github.thomasdarimont.keycloak.mcp.audit.AuditListener;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolLevel;
import com.github.thomasdarimont.keycloak.mcp.config.ClientAuth;
import com.github.thomasdarimont.keycloak.mcp.config.GrantType;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeyVault;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystem;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystemRepository;
import com.github.thomasdarimont.keycloak.mcp.keycloak.SigningKey;
import com.github.thomasdarimont.keycloak.mcp.storage.audit.AuditEventEntity;
import com.github.thomasdarimont.keycloak.mcp.storage.audit.DatabaseAuditListener;
import com.github.thomasdarimont.keycloak.mcp.storage.crypto.StorageCrypto;
import com.github.thomasdarimont.keycloak.mcp.storage.keys.DatabaseKeyVault;
import com.github.thomasdarimont.keycloak.mcp.storage.keys.SigningKeyEntity;
import com.github.thomasdarimont.keycloak.mcp.storage.systems.DatabaseKeycloakSystemRepository;
import com.github.thomasdarimont.keycloak.mcp.storage.systems.SystemEntity;

import io.quarkus.test.junit.QuarkusTest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The three storage extensions against PostgreSQL (Dev Services), looked up the way the
 * server finds them: through {@code Instance}, which {@code @LookupIfProperty} filters.
 */
@QuarkusTest
class DatabaseStorageIT {

    @Inject
    @Any
    Instance<KeycloakSystemRepository> repositories;

    @Inject
    @Any
    Instance<KeyVault> vaults;

    @Inject
    @Any
    Instance<AuditListener> listeners;

    static KeycloakSystem system(String alias, String url, Optional<String> secret, Set<String> realms) {
        return new KeycloakSystem(alias, url, GrantType.CLIENT_CREDENTIALS,
                secret.isPresent() ? ClientAuth.CLIENT_SECRET : ClientAuth.PRIVATE_KEY_JWT, "master",
                Optional.of("keycloak-mcp-server"), secret, Optional.empty(), Optional.empty(), Optional.of("tenant"),
                realms, Optional.of("26.8.1"), Optional.of("https://sso.example.com/realms/master"));
    }

    @Test
    void systemsAreStoredByAliasWithALabelAndEncryptedSecrets() {
        DatabaseKeycloakSystemRepository repo = repositories.select(DatabaseKeycloakSystemRepository.class).get();
        assertEquals("db-systems", repo.id());
        String alias = "tenant-" + UUID.randomUUID();
        KeycloakSystem tenant = system(alias, "https://sso.example.com", Optional.of("top-secret"),
                Set.of("tenant", "tenant-2"));

        SystemEntity row = repo.save(tenant, "ACME Corp.");
        assertEquals(36, row.id.length(), "surrogate id");
        assertEquals(alias, row.alias);
        assertEquals("ACME Corp.", row.name);
        assertTrue(StorageCrypto.isEncrypted(row.clientSecret), "client secret encrypted at rest: " + row.clientSecret);
        assertTrue(row.createdAt > 0 && row.updatedAt >= row.createdAt);

        assertTrue(repo.names().contains(alias));
        assertEquals(tenant, repo.find(alias).orElseThrow(), "round trip, secret decrypted");
        assertTrue(repo.all().contains(tenant));

        // settings change: same row, label kept
        KeycloakSystem moved = system(alias, "https://sso2.example.com", Optional.empty(), Set.of());
        assertEquals(row.id, repo.save(moved).id);
        assertEquals("ACME Corp.", repo.entity(alias).orElseThrow().name);
        assertEquals(moved, repo.find(alias).orElseThrow());

        // disabled rows are kept but not served
        assertTrue(repo.setEnabled(alias, false));
        assertTrue(repo.find(alias).isEmpty());
        assertFalse(repo.names().contains(alias));
        assertTrue(repo.entities().stream().anyMatch(e -> e.alias.equals(alias)));
        assertTrue(repo.setEnabled(alias, true));

        // the alias can change, the row stays
        String renamed = alias + "-renamed";
        assertTrue(repo.rename(alias, renamed));
        assertTrue(repo.find(alias).isEmpty());
        assertEquals(row.id, repo.entity(renamed).orElseThrow().id);

        assertTrue(repo.delete(renamed));
        assertFalse(repo.delete(renamed));
        assertFalse(repo.setEnabled("nope", true));
    }

    @Test
    void theVaultCreatesRotatesAndEncryptsKeysAndKeepsSecrets() {
        DatabaseKeyVault vault = vaults.select(DatabaseKeyVault.class).get();
        assertEquals("db-key-vault", vault.id());
        assertTrue(vault.supportsKeyCreation());
        String alias = "tenant-" + UUID.randomUUID();

        assertTrue(vault.findSigningKey(alias).isEmpty());
        SigningKey created = vault.createSigningKey(alias);
        SigningKey found = vault.findSigningKey(alias).orElseThrow();
        assertEquals("RS256", found.algorithm());
        assertNull(found.keyId(), "thumbprint kid");
        assertEquals(((RSAPublicKey) created.publicKey()).getModulus(),
                ((RSAPublicKey) found.publicKey()).getModulus());
        assertEquals(created.privateKey(), found.privateKey(), "PKCS#8 round trip");

        SigningKey rotated = vault.createSigningKey(alias);
        assertNotEquals(((RSAPublicKey) created.publicKey()).getModulus(),
                ((RSAPublicKey) rotated.publicKey()).getModulus());
        assertEquals(((RSAPublicKey) rotated.publicKey()).getModulus(),
                ((RSAPublicKey) vault.findSigningKey(alias).orElseThrow().publicKey()).getModulus());
        List<SigningKeyEntity> history = vault.history(alias);
        assertEquals(2, history.size());
        assertNull(history.get(0).retiredAt, "newest is current");
        assertTrue(history.get(1).retiredAt != null, "the previous key is retired, not deleted");
        assertTrue(StorageCrypto.isEncrypted(history.get(0).privateKey), "private key encrypted at rest");
        assertFalse(StorageCrypto.isEncrypted(history.get(0).publicKey), "public key in the clear");

        String name = alias + "/client-secret";
        assertTrue(vault.findSecret(name).isEmpty());
        vault.putSecret(name, "s3cr3t");
        assertEquals("s3cr3t", vault.findSecret(name).orElseThrow());
        vault.putSecret(name, "changed");
        assertEquals("changed", vault.findSecret(name).orElseThrow());
        assertTrue(vault.deleteSecret(name));
        assertTrue(vault.findSecret(name).isEmpty());
    }

    @Test
    void auditEventsBecomeRows() {
        DatabaseAuditListener audit = listeners.select(DatabaseAuditListener.class).get();
        assertEquals("db-audit", audit.id());
        String subject = UUID.randomUUID().toString();
        Caller alice = Caller.of(subject, "alice", "tenant", Set.of("realm:admin"));
        Instant at = Instant.now();
        audit.onToolCall(new AuditListener.Event(at, "keycloak_user_delete", ToolLevel.DESTRUCTIVE, "tenant-a",
                "tenant", Map.of("id", "bob", "password", "***"), "forbidden", "missing manage-users", "execute_tool",
                alice.asDelegated(), "lm-studio", "conn-1", Duration.ofMillis(42)));
        audit.onToolCall(new AuditListener.Event(at.plusMillis(1), "whoami", ToolLevel.READ, null, null, Map.of(), "ok",
                null, "direct", Caller.NONE, "-", "-", Duration.ofMillis(1)));

        List<AuditEventEntity> recent = audit.recent(2);
        assertEquals(2, recent.size());
        assertEquals("whoami", recent.get(0).tool, "newest first");
        assertNull(recent.get(0).callerSubject, "anonymous");
        assertNull(recent.get(0).args, "no arguments, no JSON");
        AuditEventEntity denied = recent.get(1);
        assertEquals("keycloak_user_delete", denied.tool);
        assertEquals("DESTRUCTIVE", denied.level);
        assertEquals("tenant-a", denied.system);
        assertEquals("forbidden", denied.outcome);
        assertEquals("missing manage-users", denied.message);
        assertEquals(subject, denied.callerSubject);
        assertEquals("alice", denied.callerName);
        assertTrue(denied.delegated);
        assertEquals(at.toEpochMilli(), denied.occurredAt);
        assertEquals(42, denied.durationMs);
        assertTrue(denied.args.contains("\"password\":\"***\""), denied.args);

        List<AuditEventEntity> mine = audit.byCaller(subject, 10);
        assertEquals(1, mine.size());
        assertTrue(audit.count() >= 2);
    }
}
