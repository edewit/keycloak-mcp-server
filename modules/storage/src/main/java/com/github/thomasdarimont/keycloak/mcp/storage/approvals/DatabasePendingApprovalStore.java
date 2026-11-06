package com.github.thomasdarimont.keycloak.mcp.storage.approvals;

import java.util.Optional;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.persistence.LockModeType;
import jakarta.persistence.PersistenceException;
import jakarta.transaction.Transactional;

import org.jboss.logging.Logger;

import com.github.thomasdarimont.keycloak.mcp.confirm.PendingApproval;
import com.github.thomasdarimont.keycloak.mcp.confirm.PendingApprovalStore;
import com.github.thomasdarimont.keycloak.mcp.storage.StorageConfig;
import com.github.thomasdarimont.keycloak.mcp.storage.StorageConfigSourceFactory;
import com.github.thomasdarimont.keycloak.mcp.storage.crypto.StorageCrypto;

import io.quarkus.arc.lookup.LookupIfProperty;
import io.quarkus.scheduler.Scheduled;

/**
 * The {@link PendingApprovalStore} of the database: one row of
 * {@code kc_mcp_pending_approval} per approval, shared by every instance on the database,
 * so the call that collects a decision may reach another instance than the one that filed
 * the request. The reservation is a row insert under the primary key, so exactly one
 * instance files a request for a key. {@code auth_req_id} is encrypted when
 * {@code kc-mcp.storage.secret-key} is set. Expired rows are removed every hour; switch
 * the store off alone with {@code kc-mcp.spi.db-approvals.enabled=false}.
 */
@ApplicationScoped
@LookupIfProperty(name = StorageConfigSourceFactory.ENABLED, stringValue = "true")
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
    public boolean reserve(String key, long until) {
        try {
            return doReserve(key, until);
        }
        catch (PersistenceException | IllegalStateException e) {
            // another instance inserted the same key first: the unique constraint said so
            LOG.debugf("Reservation of %s lost to a concurrent insert: %s", key, e.toString());
            return false;
        }
    }

    @Transactional
    boolean doReserve(String key, long until) {
        long now = System.currentTimeMillis();
        PendingApprovalEntity e = PendingApprovalEntity.findById(key, LockModeType.PESSIMISTIC_WRITE);
        if (e != null && e.expiresAt > now) {
            return false;
        }
        if (e == null) {
            e = new PendingApprovalEntity();
            e.id = key;
            e.createdAt = now;
        }
        e.authReqId = null;
        e.requestId = null;
        e.code = null;
        e.bindingMessage = null;
        e.issuer = null;
        e.loginHint = null;
        e.callerSubject = null;
        e.callerIssuer = null;
        e.operation = null;
        e.system = null;
        e.realm = null;
        e.intervalSeconds = 0;
        e.expiresAt = until;
        e.createdAt = now;
        e.persist();
        return true;
    }

    @Override
    @Transactional
    public void put(PendingApproval a) {
        PendingApprovalEntity e = PendingApprovalEntity.findById(a.key());
        if (e == null) {
            e = new PendingApprovalEntity();
            e.id = a.key();
        }
        e.authReqId = crypto.protect(a.authReqId());
        e.requestId = a.requestId();
        e.code = a.code();
        e.bindingMessage = a.bindingMessage();
        e.issuer = a.issuer();
        e.loginHint = a.loginHint();
        e.callerSubject = a.callerSubject();
        e.callerIssuer = a.callerIssuer();
        e.operation = a.operation();
        e.system = a.system();
        e.realm = a.realm();
        e.expiresAt = a.expiresAt();
        e.intervalSeconds = a.intervalSeconds();
        e.createdAt = a.createdAt();
        e.persist();
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
    public boolean remove(String key) {
        return PendingApprovalEntity.delete("id = ?1 and expiresAt > ?2", key, System.currentTimeMillis()) > 0;
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
        return new PendingApproval(e.id, e.authReqId == null ? null : crypto.reveal(e.authReqId), e.requestId, e.code,
                e.bindingMessage, e.issuer, e.loginHint, e.callerSubject, e.callerIssuer, e.operation, e.system,
                e.realm, e.expiresAt, e.intervalSeconds, e.createdAt);
    }
}
