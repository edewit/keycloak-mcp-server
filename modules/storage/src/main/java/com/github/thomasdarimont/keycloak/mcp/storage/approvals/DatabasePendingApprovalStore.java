package com.github.thomasdarimont.keycloak.mcp.storage.approvals;

import java.util.Optional;
import java.util.UUID;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.persistence.PersistenceException;
import jakarta.transaction.Transactional;

import org.jboss.logging.Logger;

import com.github.thomasdarimont.keycloak.mcp.confirm.PendingApproval;
import com.github.thomasdarimont.keycloak.mcp.confirm.PendingApprovalStore;
import com.github.thomasdarimont.keycloak.mcp.storage.StorageConfig;
import com.github.thomasdarimont.keycloak.mcp.storage.StorageEnabledInterceptorFactory;
import com.github.thomasdarimont.keycloak.mcp.storage.crypto.StorageCrypto;

import io.quarkus.arc.lookup.LookupIfProperty;
import io.quarkus.scheduler.Scheduled;

/**
 * The {@link PendingApprovalStore} of the database: one row of
 * {@code kc_mcp_pending_approval} per approval, shared by every instance on the database,
 * so the call that collects a decision may reach another instance than the one that filed
 * the request. Every change is one conditional statement on the row: the reservation is
 * an insert under the primary key (or an update of an expired row), and put, claim,
 * release and remove only touch the row while it carries the caller's generation.
 * {@code auth_req_id} is encrypted when {@code kc-mcp.storage.secret-key} is set. Expired
 * rows are removed every hour; switch the store off alone with
 * {@code kc-mcp.spi.db-approvals.enabled=false}.
 */
@ApplicationScoped
@LookupIfProperty(name = StorageEnabledInterceptorFactory.ENABLED, stringValue = "true")
public class DatabasePendingApprovalStore implements PendingApprovalStore {

    public static final String ID = "db-approvals";

    private static final Logger LOG = Logger.getLogger(DatabasePendingApprovalStore.class);

    private final StorageCrypto crypto;

    @Inject
    StorageConfig storage;

    @Inject
    public DatabasePendingApprovalStore(StorageCrypto crypto) {
        this.crypto = crypto;
    }

    @Override
    public String id() {
        return ID;
    }

    @Override
    public String displayName() {
        return "Pending approvals in the database";
    }

    @Override
    public String description() {
        return "Keeps the CIBA confirmer's pending approvals in kc_mcp_pending_approval, shared by all instances.";
    }

    @Override
    public Optional<String> reserve(String key, long until) {
        String generation = UUID.randomUUID().toString();
        try {
            return doReserve(key, generation, until) ? Optional.of(generation) : Optional.empty();
        }
        catch (PersistenceException | IllegalStateException e) {
            // another instance inserted the same key first: the primary key said so
            LOG.debugf("Reservation of %s lost to a concurrent insert: %s", key, e.toString());
            return Optional.empty();
        }
    }

    @Transactional
    boolean doReserve(String key, String generation, long until) {
        long now = System.currentTimeMillis();
        // take over an expired row in one statement; only one instance's update matches
        int taken = PendingApprovalEntity.update("generation = ?1, authReqId = null, requestId = null, code = null,"
                + " bindingMessage = null, issuer = null, loginHint = null, callerSubject = null, callerIssuer = null,"
                + " operation = null, operationHash = null, system = null, realm = null, intervalSeconds = 0,"
                + " claimedBy = null, claimedUntil = null, approvedAt = null, expiresAt = ?2, createdAt = ?3"
                + " where id = ?4 and expiresAt <= ?3", generation, until, now, key);
        if (taken == 1) {
            return true;
        }
        if (PendingApprovalEntity.count("id = ?1", key) > 0) {
            return false;
        }
        PendingApprovalEntity e = new PendingApprovalEntity();
        e.id = key;
        e.generation = generation;
        e.expiresAt = until;
        e.createdAt = now;
        e.persistAndFlush();
        return true;
    }

    @Override
    @Transactional
    public boolean put(PendingApproval a) {
        return PendingApprovalEntity.update(
                "authReqId = ?1, requestId = ?2, code = ?3, bindingMessage = ?4,"
                        + " issuer = ?5, loginHint = ?6, callerSubject = ?7, callerIssuer = ?8, operation = ?9,"
                        + " operationHash = ?10, system = ?11, realm = ?12, expiresAt = ?13, intervalSeconds = ?14,"
                        + " createdAt = ?15 where id = ?16 and generation = ?17 and expiresAt > ?18",
                crypto.protect(a.authReqId()), a.requestId(), a.code(), a.bindingMessage(), a.issuer(), a.loginHint(),
                a.callerSubject(), a.callerIssuer(), a.operation(), a.operationHash(), a.system(), a.realm(),
                a.expiresAt(), a.intervalSeconds(), a.createdAt(), a.key(), a.generation(),
                System.currentTimeMillis()) == 1;
    }

    @Override
    @Transactional
    public Optional<PendingApproval> find(String key) {
        return PendingApprovalEntity.<PendingApprovalEntity>findByIdOptional(key)
            .filter(e -> e.expiresAt > System.currentTimeMillis())
            .map(this::toApproval);
    }

    @Override
    @Transactional
    public boolean claim(String key, String generation, String collector, long until) {
        long now = System.currentTimeMillis();
        return PendingApprovalEntity.update(
                "claimedBy = ?1, claimedUntil = ?2 where id = ?3 and generation = ?4"
                        + " and expiresAt > ?5 and (claimedBy is null or claimedBy = ?1 or claimedUntil <= ?5)",
                collector, until, key, generation, now) == 1;
    }

    @Override
    @Transactional
    public boolean markApproved(String key, String generation) {
        long now = System.currentTimeMillis();
        return PendingApprovalEntity.update("approvedAt = ?1 where id = ?2 and generation = ?3 and expiresAt > ?1", now,
                key, generation) == 1;
    }

    @Override
    @Transactional
    public void release(String key, String generation, String collector) {
        PendingApprovalEntity.update(
                "claimedBy = null, claimedUntil = null where id = ?1 and generation = ?2" + " and claimedBy = ?3", key,
                generation, collector);
    }

    @Override
    @Transactional
    public boolean remove(String key, String generation) {
        long now = System.currentTimeMillis();
        long live = PendingApprovalEntity.delete("id = ?1 and generation = ?2 and expiresAt > ?3", key, generation,
                now);
        if (live == 0) {
            PendingApprovalEntity.delete("id = ?1 and generation = ?2", key, generation);
        }
        return live > 0;
    }

    @Override
    @Transactional
    public long deleteExpired(long now) {
        return PendingApprovalEntity.delete("expiresAt <= ?1", now);
    }

    @Override
    @Transactional
    public long countLive(long now) {
        return PendingApprovalEntity.count("expiresAt > ?1", now);
    }

    @Scheduled(every = "1h", delayed = "10m", concurrentExecution = Scheduled.ConcurrentExecution.SKIP)
    void purge() {
        if (storage == null || !storage.enabled()) {
            // the bean exists, the scheduler calls it, but without a datasource there is
            // nothing to purge
            return;
        }
        try {
            long n = deleteExpired(System.currentTimeMillis());
            if (n > 0) {
                LOG.infof("Removed %d expired pending approvals", n);
            }
        }
        catch (RuntimeException e) {
            LOG.warnf(e, "Pending approvals: purge failed, next attempt in an hour: %s", e.getMessage());
        }
    }

    private PendingApproval toApproval(PendingApprovalEntity e) {
        return new PendingApproval(e.id, e.generation, e.authReqId == null ? null : crypto.reveal(e.authReqId),
                e.requestId, e.code, e.bindingMessage, e.issuer, e.loginHint, e.callerSubject, e.callerIssuer,
                e.operation, e.operationHash, e.system, e.realm, e.expiresAt, e.intervalSeconds, e.createdAt,
                e.claimedBy, e.claimedUntil == null ? 0 : e.claimedUntil, e.approvedAt != null);
    }
}
