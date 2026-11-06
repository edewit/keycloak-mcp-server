package com.github.thomasdarimont.keycloak.mcp.storage.web;

import java.util.Optional;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.transaction.Transactional;

import org.jboss.logging.Logger;

import com.github.thomasdarimont.keycloak.mcp.storage.StorageConfig;
import com.github.thomasdarimont.keycloak.mcp.storage.StorageConfigSourceFactory;
import com.github.thomasdarimont.keycloak.mcp.storage.crypto.StorageCrypto;
import com.github.thomasdarimont.keycloak.mcp.web.UserSession;
import com.github.thomasdarimont.keycloak.mcp.web.UserSessionStore;

import io.quarkus.arc.lookup.LookupIfProperty;
import io.quarkus.scheduler.Scheduled;

/**
 * The {@link UserSessionStore} of the database: one row of {@code kc_mcp_user_session}
 * per browser session of the management UI, tokens encrypted at rest when
 * {@code kc-mcp.storage.secret-key} is set. Expired rows are removed every hour; switch
 * the store off alone with {@code kc-mcp.spi.db-user-sessions.enabled=false}.
 */
@ApplicationScoped
@LookupIfProperty(name = StorageConfigSourceFactory.ENABLED, stringValue = "true")
public class DatabaseUserSessionStore implements UserSessionStore {

    public static final String ID = "db-user-sessions";

    private static final Logger LOG = Logger.getLogger(DatabaseUserSessionStore.class);

    private final StorageCrypto crypto;

    @Inject
    StorageConfig storage;

    @Inject
    public DatabaseUserSessionStore(StorageCrypto crypto) {
        this.crypto = crypto;
    }

    @Override
    public String id() {
        return ID;
    }

    @Override
    public String displayName() {
        return "Database user sessions";
    }

    @Override
    public String description() {
        return "browser sessions of the management UI in the database"
                + (crypto.enabled() ? ", tokens encrypted at rest" : ", not encrypted (set kc-mcp.storage.secret-key)");
    }

    @Override
    @Transactional
    public void save(UserSession session) {
        UserSessionEntity e = UserSessionEntity.findById(session.id());
        if (e == null) {
            e = new UserSessionEntity();
            e.id = session.id();
            e.createdAt = session.createdAt();
        }
        e.idp = session.idp();
        e.issuer = session.issuer();
        e.subject = session.subject();
        e.sid = session.sid();
        e.idToken = crypto.protect(session.idToken());
        e.accessToken = session.accessToken() == null ? null : crypto.protect(session.accessToken());
        e.refreshToken = session.refreshToken() == null ? null : crypto.protect(session.refreshToken());
        e.accessTokenExpiresIn = session.accessTokenExpiresIn();
        e.scope = session.scope();
        e.expiresAt = session.expiresAt();
        e.persist();
    }

    @Override
    @Transactional
    public Optional<UserSession> find(String id) {
        if (id == null || id.isBlank()) {
            return Optional.empty();
        }
        return UserSessionEntity.<UserSessionEntity>findByIdOptional(id)
            .filter(e -> e.expiresAt > System.currentTimeMillis())
            .map(this::toSession);
    }

    @Override
    @Transactional
    public void delete(String id) {
        if (id != null && !id.isBlank()) {
            UserSessionEntity.deleteById(id);
        }
    }

    @Override
    @Transactional
    public long countLive(long now) {
        return UserSessionEntity.count("expiresAt > ?1", now);
    }

    @Override
    @Transactional
    public long deleteExpired(long now) {
        return UserSessionEntity.delete("expiresAt < ?1", now);
    }

    @Override
    @Transactional
    public long deleteBySession(String issuer, String sid) {
        if (issuer == null || sid == null || sid.isBlank()) {
            return 0;
        }
        return UserSessionEntity.delete("issuer = ?1 and sid = ?2", issuer, sid);
    }

    @Override
    @Transactional
    public long deleteBySubject(String issuer, String subject) {
        if (issuer == null || subject == null || subject.isBlank()) {
            return 0;
        }
        return UserSessionEntity.delete("issuer = ?1 and subject = ?2", issuer, subject);
    }

    @Scheduled(every = "1h", delayed = "2m", concurrentExecution = Scheduled.ConcurrentExecution.SKIP)
    void purge() {
        if (storage == null || !storage.enabled()) {
            // the bean exists, the scheduler calls it, but without a datasource there is
            // nothing to purge
            return;
        }
        try {
            long removed = deleteExpired(System.currentTimeMillis());
            if (removed > 0) {
                LOG.infof("User sessions: removed %d expired sessions", removed);
            }
        }
        catch (RuntimeException e) {
            LOG.warnf(e, "User sessions: purge failed, next attempt in an hour: %s", e.getMessage());
        }
    }

    private UserSession toSession(UserSessionEntity e) {
        return new UserSession(e.id, e.idp, e.issuer, e.subject, e.sid, crypto.reveal(e.idToken),
                e.accessToken == null ? null : crypto.reveal(e.accessToken),
                e.refreshToken == null ? null : crypto.reveal(e.refreshToken), e.accessTokenExpiresIn, e.scope,
                e.createdAt, e.expiresAt);
    }
}
