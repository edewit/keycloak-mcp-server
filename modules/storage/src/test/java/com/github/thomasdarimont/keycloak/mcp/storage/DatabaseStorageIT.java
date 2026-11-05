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
import com.github.thomasdarimont.keycloak.mcp.audit.AuditEvent;
import com.github.thomasdarimont.keycloak.mcp.audit.AuditListener;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolLevel;
import com.github.thomasdarimont.keycloak.mcp.config.ClientAuth;
import com.github.thomasdarimont.keycloak.mcp.config.GrantType;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeyVault;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystem;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystemRepository;
import com.github.thomasdarimont.keycloak.mcp.keycloak.SigningKey;
import com.github.thomasdarimont.keycloak.mcp.storage.audit.AuditEventEntity;
import com.github.thomasdarimont.keycloak.mcp.storage.audit.AuditRetention;
import com.github.thomasdarimont.keycloak.mcp.storage.audit.DatabaseAuditListener;
import com.github.thomasdarimont.keycloak.mcp.storage.crypto.StorageCrypto;
import com.github.thomasdarimont.keycloak.mcp.storage.keys.DatabaseKeyVault;
import com.github.thomasdarimont.keycloak.mcp.storage.keys.SecretEntity;
import com.github.thomasdarimont.keycloak.mcp.storage.keys.SigningKeyEntity;
import com.github.thomasdarimont.keycloak.mcp.storage.systems.DatabaseKeycloakSystemRepository;
import com.github.thomasdarimont.keycloak.mcp.storage.systems.SystemEntity;

import io.quarkus.narayana.jta.QuarkusTransaction;
import io.quarkus.runtime.BlockingOperationControl;
import io.quarkus.runtime.IOThreadDetector;
import io.quarkus.test.junit.QuarkusTest;
import io.vertx.core.Context;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
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

    @Inject
    AuditRetention retention;

    @Inject
    StorageRekey rekey;

    @Inject
    StorageCrypto crypto;

    static KeycloakSystem system(String alias, String url, Optional<String> secret, Set<String> realms) {
        return new KeycloakSystem(alias, url, GrantType.CLIENT_CREDENTIALS,
                secret.isPresent() ? ClientAuth.CLIENT_SECRET : ClientAuth.PRIVATE_KEY_JWT, "master",
                Optional.of("keycloak-mcp-server"), secret, Optional.empty(), Optional.empty(), Optional.of("tenant"),
                realms, Optional.of("26.8.2"), Optional.of("https://sso.example.com/realms/master"));
    }

    @Test
    void systemsAreStoredByAliasWithALabelAndEncryptedSecrets() {
        DatabaseKeycloakSystemRepository repo = repositories.select(DatabaseKeycloakSystemRepository.class).get();
        assertEquals("db-systems", repo.id());
        String alias = "tenant-" + UUID.randomUUID();
        KeycloakSystem tenant = system(alias, "https://sso.example.com", Optional.of("top-secret"),
                Set.of("tenant", "tenant-2"));

        SystemEntity row = repo.saveEntity(tenant.withDisplayName("ACME Corp.").withDescription("ACME's Keycloak"));
        assertEquals(36, row.id.length(), "surrogate id");
        assertEquals(alias, row.alias);
        assertEquals("ACME Corp.", row.name);
        assertEquals("ACME's Keycloak", row.description);
        var stamps = repo.timestamps(alias).orElseThrow();
        assertEquals(row.createdAt, stamps.createdAt().toEpochMilli());
        assertEquals(row.updatedAt, stamps.updatedAt().toEpochMilli());
        assertTrue(repo.timestamps("nope-" + alias).isEmpty());
        assertTrue(StorageCrypto.isEncrypted(row.clientSecret), "client secret encrypted at rest: " + row.clientSecret);
        assertTrue(row.createdAt > 0 && row.updatedAt >= row.createdAt);

        assertTrue(repo.names().contains(alias));
        assertEquals(tenant.withDisplayName("ACME Corp.").withDescription("ACME's Keycloak"),
                repo.find(alias).orElseThrow(), "round trip, secret decrypted, label and description attached");
        assertTrue(repo.all().contains(tenant.withDisplayName("ACME Corp.").withDescription("ACME's Keycloak")));

        // settings change: same row, label kept
        KeycloakSystem moved = system(alias, "https://sso2.example.com", Optional.empty(), Set.of());
        assertEquals(row.id, repo.saveEntity(moved).id);
        assertEquals("ACME Corp.", repo.entity(alias).orElseThrow().name, "no label in the update keeps the old one");
        assertEquals(moved.withDisplayName("ACME Corp.").withDescription("ACME's Keycloak"),
                repo.find(alias).orElseThrow(), "the description is kept as well");
        assertEquals("ACME Inc.", repo.save(moved.withDisplayName("ACME Inc.")).displayName().orElseThrow());
        assertTrue(repo.timestamps(alias).orElseThrow().updatedAt().toEpochMilli() >= row.updatedAt);

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

        // on an event loop thread the repository serves its snapshot and never touches
        // the database
        repo.names(); // a warm snapshot
        BlockingOperationControl.setIoThreadDetector(new IOThreadDetector[] { () -> true });
        try {
            assertTrue(repo.names().contains(renamed), "served from the snapshot");
            KeycloakSystem fromSnapshot = repo.find(renamed).orElseThrow();
            assertEquals(renamed, fromSnapshot.name());
            assertEquals("ACME Inc.", fromSnapshot.displayName().orElseThrow());
            assertTrue(repo.find("nope-" + alias).isEmpty(), "unknown aliases do not throw either");
            assertThrows(RuntimeException.class, () -> repo.delete(renamed), "writes stay worker-thread only");
        }
        finally {
            // what Quarkus installs: the Vert.x event loop check
            BlockingOperationControl.setIoThreadDetector(new IOThreadDetector[] { Context::isOnEventLoopThread });
        }

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

        // the JWKS publishes the current key first and the retired one for the grace
        // period, so another instance still signing with it is accepted
        List<SigningKey> published = vault.publishedSigningKeys(alias);
        assertEquals(2, published.size());
        assertEquals(((RSAPublicKey) rotated.publicKey()).getModulus(),
                ((RSAPublicKey) published.get(0).publicKey()).getModulus(), "current first");
        assertEquals(((RSAPublicKey) created.publicKey()).getModulus(),
                ((RSAPublicKey) published.get(1).publicKey()).getModulus(), "retired, within the grace period");
        long longAgo = System.currentTimeMillis() - Duration.ofDays(2).toMillis();
        QuarkusTransaction.requiringNew()
            .run(() -> SigningKeyEntity.update("retiredAt = ?1 where id = ?2", longAgo, history.get(1).id));
        assertEquals(1, vault.publishedSigningKeys(alias).size(), "retired beyond the grace period, dropped");
        assertEquals(2, vault.history(alias).size(), "but kept in the history");

        String name = alias + "/client-secret";
        assertTrue(vault.supportsSecretStorage());
        assertTrue(vault.findSecret(name).isEmpty());
        vault.putSecret(name, "s3cr3t");
        assertEquals("s3cr3t", vault.findSecret(name).orElseThrow());
        assertTrue(vault.secretNames().contains(name), "names, never values");
        vault.putSecret(name, "changed");
        assertEquals("changed", vault.findSecret(name).orElseThrow());
        assertTrue(vault.deleteSecret(name));
        assertFalse(vault.deleteSecret(name));
        assertTrue(vault.findSecret(name).isEmpty());
        assertFalse(vault.secretNames().contains(name));
    }

    @Test
    void auditEventsBecomeRows() {
        DatabaseAuditListener audit = listeners.select(DatabaseAuditListener.class).get();
        assertEquals("db-audit", audit.id());
        String subject = UUID.randomUUID().toString();
        Caller alice = Caller.of(subject, "alice", "tenant", Set.of("realm:admin"));
        Instant at = Instant.now();
        audit.onToolCall(new AuditEvent(at, "keycloak_user_delete", ToolLevel.DESTRUCTIVE, "tenant-a", "tenant",
                Map.of("id", "bob", "password", "***"), "forbidden", "missing manage-users", "execute_tool",
                alice.asDelegated(), "lm-studio", "conn-1", Duration.ofMillis(42)));
        audit.onToolCall(new AuditEvent(at.plusMillis(1), "whoami", ToolLevel.READ, null, null, Map.of(), "ok", null,
                "direct", Caller.NONE, "-", "-", Duration.ofMillis(1)));

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

    @Test
    void rekeyRewritesRowsUnderThePreviousKeyAndReportsUnknownOnes() {
        DatabaseKeyVault vault = vaults.select(DatabaseKeyVault.class).get();
        String current = crypto.currentKeyId().orElseThrow();
        assertTrue(crypto.hasPreviousKeys(), "kc-mcp.storage.previous-secret-keys of the test configuration");
        String fromOld = "rekey-old-" + UUID.randomUUID();
        String fromStranger = "rekey-stranger-" + UUID.randomUUID();
        String oldValue = new StorageCrypto("old-passphrase").protect("written before the rotation");
        String strangerValue = new StorageCrypto("nobody-knows").protect("written with a lost key");
        String strangerKid = StorageCrypto.keyIdOf(strangerValue).orElseThrow();
        QuarkusTransaction.requiringNew().run(() -> {
            for (String[] row : new String[][] { { fromOld, oldValue }, { fromStranger, strangerValue } }) {
                SecretEntity e = new SecretEntity();
                e.name = row[0];
                e.value = row[1];
                e.createdAt = e.updatedAt = System.currentTimeMillis();
                e.persist();
            }
        });

        assertEquals("written before the rotation", vault.findSecret(fromOld).orElseThrow(), "previous key decrypts");
        assertThrows(IllegalStateException.class, () -> vault.findSecret(fromStranger), "unknown key does not");
        StorageRekey.Status before = rekey.status();
        assertTrue(before.encryption() && before.previousKeys());
        assertEquals(current, before.currentKeyId());
        assertTrue(before.keyIds().get("kc_mcp_secret").containsKey(strangerKid), before.keyIds().toString());

        StorageRekey.Result result = rekey.rekey();
        assertEquals(current, result.currentKeyId());
        assertTrue(result.secrets() >= 1, result.toString());
        assertEquals(1L, result.remaining().get(strangerKid), "the row under the lost key is reported, not touched");

        SecretEntity rewritten = QuarkusTransaction.requiringNew().call(() -> SecretEntity.findById(fromOld));
        assertEquals(current, StorageCrypto.keyIdOf(rewritten.value).orElseThrow(), "now under the current key");
        assertEquals("written before the rotation", vault.findSecret(fromOld).orElseThrow());
        assertEquals(0, rekey.rekey().secrets(), "idempotent");

        QuarkusTransaction.requiringNew().run(() -> SecretEntity.deleteById(fromStranger));
        assertTrue(vault.deleteSecret(fromOld));
    }

    @Test
    void retentionRemovesOldEventsOnly() {
        DatabaseAuditListener audit = listeners.select(DatabaseAuditListener.class).get();
        assertEquals(30, retention.retentionDays(), "kc-mcp.spi.db-audit.retention-days of the test configuration");
        String subject = UUID.randomUUID().toString();
        Caller caller = Caller.of(subject, "old-timer", "tenant", Set.of());
        Instant now = Instant.now();
        for (int daysAgo : new int[] { 31, 400, 29, 0 }) {
            audit.onToolCall(new AuditEvent(now.minus(Duration.ofDays(daysAgo)), "whoami", ToolLevel.READ, null, null,
                    Map.of("daysAgo", daysAgo), "ok", null, "direct", caller, "-", "-", Duration.ofMillis(1)));
        }
        assertEquals(4, audit.byCaller(subject, 10).size());

        assertTrue(retention.purge() >= 2, "the two events beyond 30 days");
        List<AuditEventEntity> left = audit.byCaller(subject, 10);
        assertEquals(2, left.size());
        assertTrue(left.stream().allMatch(e -> e.occurredAt >= now.minus(Duration.ofDays(30)).toEpochMilli()));

        assertEquals(0, audit.purgeOlderThan(now.minus(Duration.ofDays(30)).toEpochMilli()), "nothing older left");
        assertTrue(audit.purgeOlderThan(now.minus(Duration.ofDays(1)).toEpochMilli()) >= 1, "an explicit cutoff");
    }
}
