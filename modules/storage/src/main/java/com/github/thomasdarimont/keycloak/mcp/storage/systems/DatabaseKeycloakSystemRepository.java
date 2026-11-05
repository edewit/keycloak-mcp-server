package com.github.thomasdarimont.keycloak.mcp.storage.systems;

import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.locks.ReentrantLock;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.transaction.Transactional;

import org.jboss.logging.Logger;

import com.github.thomasdarimont.keycloak.mcp.config.ClientAuth;
import com.github.thomasdarimont.keycloak.mcp.config.GrantType;
import com.github.thomasdarimont.keycloak.mcp.config.McpServerConfig;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystem;
import com.github.thomasdarimont.keycloak.mcp.keycloak.MutableKeycloakSystemRepository;
import com.github.thomasdarimont.keycloak.mcp.keycloak.SystemTimestamps;
import com.github.thomasdarimont.keycloak.mcp.spi.ProviderConfig;
import com.github.thomasdarimont.keycloak.mcp.storage.StorageConfigSourceFactory;
import com.github.thomasdarimont.keycloak.mcp.storage.crypto.StorageCrypto;

import io.quarkus.arc.lookup.LookupIfProperty;
import io.quarkus.narayana.jta.QuarkusTransaction;
import io.quarkus.runtime.BlockingOperationControl;
import io.vertx.core.json.JsonArray;

/**
 * Keycloak systems from the {@code kc_mcp_system} table: what a control plane writes
 * through {@link #save} and {@link #delete} (a {@link MutableKeycloakSystemRepository},
 * so the admin API finds it). A row's {@code alias} is what {@link KeycloakSystem#name()}
 * carries, its {@code name} the {@link KeycloakSystem#displayName()}. Active only with
 * {@code kc-mcp.storage.enabled=true} and, like every repository,
 * {@code kc-mcp.dynamic-systems=true}. Client secrets and passwords are encrypted at rest
 * when {@code kc-mcp.storage.secret-key} is set.
 * <p>
 * Reads serve a snapshot of the enabled rows that is reloaded when older than
 * {@code kc-mcp.spi.db-systems.cache-seconds} (10 by default; a write through this
 * instance reloads at once), so a tool call costs no query, and a system registered on
 * another replica shows up within that time. The server asks repositories from event loop
 * threads too (the {@code tools/list} filter), where no database call is allowed: there
 * the current snapshot is served as is and a refresh is left to a worker thread.
 */
@ApplicationScoped
@LookupIfProperty(name = StorageConfigSourceFactory.ENABLED, stringValue = "true")
public class DatabaseKeycloakSystemRepository implements MutableKeycloakSystemRepository {

    public static final String ID = "db-systems";

    /** Default of {@code kc-mcp.spi.db-systems.cache-seconds}. */
    public static final int DEFAULT_CACHE_SECONDS = 10;

    private static final String ENABLED_IN_ORDER = "enabled = true order by createdAt, alias";

    private static final Logger LOG = Logger.getLogger(DatabaseKeycloakSystemRepository.class);

    /** The enabled systems by alias as last read; {@code loadedAt} 0 means stale. */
    private record Snapshot(Map<String, KeycloakSystem> systems, long loadedAt, boolean loaded) {
        static final Snapshot EMPTY = new Snapshot(Map.of(), 0, false);
    }

    private final StorageCrypto crypto;
    private final long cacheMillis;
    private final ReentrantLock reloading = new ReentrantLock();
    private volatile Snapshot snapshot = Snapshot.EMPTY;

    @Inject
    public DatabaseKeycloakSystemRepository(StorageCrypto crypto, McpServerConfig serverConfig) {
        this(crypto,
                ProviderConfig.forExtension(ID, serverConfig.spi()).getInt("cache-seconds", DEFAULT_CACHE_SECONDS));
    }

    /**
     * @param cacheSeconds how long a snapshot of the rows is served before it is reloaded
     */
    public DatabaseKeycloakSystemRepository(StorageCrypto crypto, int cacheSeconds) {
        this.crypto = crypto;
        this.cacheMillis = Math.max(0, cacheSeconds) * 1000L;
    }

    @Override
    public String id() {
        return ID;
    }

    @Override
    public String displayName() {
        return "Database systems";
    }

    @Override
    public String description() {
        return "Keycloak systems from the kc_mcp_system table";
    }

    /** Aliases of the enabled systems, oldest first. */
    @Override
    public List<String> names() {
        return List.copyOf(current().keySet());
    }

    @Override
    public Optional<KeycloakSystem> find(String alias) {
        return Optional.ofNullable(current().get(alias));
    }

    @Override
    public List<KeycloakSystem> all() {
        return List.copyOf(current().values());
    }

    /**
     * The snapshot, reloaded when stale and the thread may block; on an event loop thread
     * the snapshot as it is, with the reload handed to a virtual thread.
     */
    private Map<String, KeycloakSystem> current() {
        Snapshot s = snapshot;
        if (s.loaded() && System.currentTimeMillis() - s.loadedAt() < cacheMillis) {
            return s.systems();
        }
        if (!BlockingOperationControl.isBlockingAllowed()) {
            if (!s.loaded()) {
                LOG.debug("Systems asked on an event loop thread before the first load; reloading in the background");
            }
            Thread.ofVirtual().name("kc-mcp-db-systems-reload").start(this::reload);
            return s.systems();
        }
        return reload();
    }

    /**
     * Reads the enabled rows in a transaction of its own; concurrent callers share one
     * read.
     */
    Map<String, KeycloakSystem> reload() {
        reloading.lock();
        try {
            Snapshot s = snapshot;
            if (s.loaded() && System.currentTimeMillis() - s.loadedAt() < cacheMillis) {
                return s.systems();
            }
            Map<String, KeycloakSystem> loaded = QuarkusTransaction.requiringNew().call(() -> {
                Map<String, KeycloakSystem> out = new java.util.LinkedHashMap<>();
                for (SystemEntity e : SystemEntity.<SystemEntity>list(ENABLED_IN_ORDER)) {
                    out.put(e.alias, toSystem(e));
                }
                return java.util.Collections.unmodifiableMap(out);
            });
            snapshot = new Snapshot(loaded, System.currentTimeMillis(), true);
            return loaded;
        }
        catch (RuntimeException e) {
            LOG.warnf("Cannot read the Keycloak systems from the database: %s", e.toString());
            return snapshot.systems();
        }
        finally {
            reloading.unlock();
        }
    }

    /** Forgets the snapshot after a write, so the next read sees the change. */
    private void invalidate() {
        snapshot = new Snapshot(snapshot.systems(), 0, snapshot.loaded());
    }

    /** Every stored system, disabled ones included, oldest first. */
    @Transactional
    public List<SystemEntity> entities() {
        return SystemEntity.list("order by createdAt, alias");
    }

    /** The row of an alias, enabled or not. */
    @Transactional
    public Optional<SystemEntity> entity(String alias) {
        return SystemEntity.<SystemEntity>find("alias = ?1", alias).firstResultOptional();
    }

    /**
     * Adds or replaces the system of an alias ({@link KeycloakSystem#name()}); the
     * enabled flag of an existing row is kept, and so is its label when the system brings
     * none. A replaced system is reconnected by the server on its next use.
     */
    @Override
    @Transactional
    public KeycloakSystem save(KeycloakSystem system) {
        return toSystem(saveEntity(system));
    }

    /** {@link #save} returning the row. */
    @Transactional
    public SystemEntity saveEntity(KeycloakSystem system) {
        long now = System.currentTimeMillis();
        SystemEntity e = entity(system.name()).orElse(null);
        if (e == null) {
            e = new SystemEntity();
            e.id = UUID.randomUUID().toString();
            e.alias = system.name();
            e.createdAt = now;
        }
        if (system.displayName().isPresent()) {
            e.name = system.displayName().get();
        }
        if (system.description().isPresent()) {
            e.description = system.description().get();
        }
        e.url = system.url();
        e.grantType = system.grantType().oauthValue();
        e.clientAuth = system.clientAuth().name().toLowerCase(Locale.ROOT);
        e.authRealm = system.authRealm();
        e.clientId = system.clientId().orElse(null);
        e.clientSecret = crypto.protect(system.clientSecret().orElse(null));
        e.username = system.username().orElse(null);
        e.password = crypto.protect(system.password().orElse(null));
        e.defaultRealm = system.defaultRealm().orElse(null);
        e.allowedRealms = system.allowedRealms().isEmpty() ? null
                : new JsonArray(system.allowedRealms().stream().sorted().toList()).encode();
        e.version = system.version().orElse(null);
        e.issuer = system.issuer().orElse(null);
        e.updatedAt = now;
        e.persist();
        invalidate();
        return e;
    }

    /**
     * Gives a system a new alias; entries and the {@code system} argument follow, signing
     * keys and audit rows keep the old one. False when unknown.
     */
    @Transactional
    public boolean rename(String alias, String newAlias) {
        SystemEntity e = entity(alias).orElse(null);
        if (e == null) {
            return false;
        }
        e.alias = newAlias.trim();
        e.updatedAt = System.currentTimeMillis();
        invalidate();
        return true;
    }

    /** Serves or hides a system without deleting it; false when unknown. */
    @Transactional
    public boolean setEnabled(String alias, boolean enabled) {
        SystemEntity e = entity(alias).orElse(null);
        if (e == null) {
            return false;
        }
        e.enabled = enabled;
        e.updatedAt = System.currentTimeMillis();
        invalidate();
        return true;
    }

    /** Removes a system; false when unknown. Its signing keys stay in the vault. */
    @Override
    @Transactional
    public boolean delete(String alias) {
        boolean deleted = SystemEntity.delete("alias = ?1", alias) > 0;
        invalidate();
        return deleted;
    }

    KeycloakSystem toSystem(SystemEntity e) {
        return KeycloakSystem.builder(e.alias, e.url)
            .grantType(GrantType.parse(e.grantType))
            .clientAuth(ClientAuth.parse(e.clientAuth))
            .authRealm(e.authRealm)
            .clientId(e.clientId)
            .clientSecret(crypto.reveal(e.clientSecret))
            .username(e.username)
            .password(crypto.reveal(e.password))
            .defaultRealm(e.defaultRealm)
            .allowedRealms(realms(e.allowedRealms))
            .version(e.version)
            .issuer(e.issuer)
            .displayName(e.name)
            .description(e.description)
            .build();
    }

    /** When the row was created and last changed. */
    @Override
    @Transactional
    public Optional<SystemTimestamps> timestamps(String alias) {
        return entity(alias)
            .map(e -> new SystemTimestamps(Instant.ofEpochMilli(e.createdAt), Instant.ofEpochMilli(e.updatedAt)));
    }

    private static Set<String> realms(String json) {
        if (json == null || json.isBlank()) {
            return Set.of();
        }
        Set<String> out = new LinkedHashSet<>();
        JsonArray array = new JsonArray(json);
        for (int i = 0; i < array.size(); i++) {
            out.add(array.getString(i));
        }
        return Set.copyOf(out);
    }

}
