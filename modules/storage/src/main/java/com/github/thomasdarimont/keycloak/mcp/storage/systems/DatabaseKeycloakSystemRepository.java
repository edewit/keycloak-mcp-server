package com.github.thomasdarimont.keycloak.mcp.storage.systems;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.transaction.Transactional;

import com.github.thomasdarimont.keycloak.mcp.config.ClientAuth;
import com.github.thomasdarimont.keycloak.mcp.config.GrantType;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystem;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystemRepository;
import com.github.thomasdarimont.keycloak.mcp.storage.StorageConfigSourceFactory;
import com.github.thomasdarimont.keycloak.mcp.storage.crypto.StorageCrypto;

import io.quarkus.arc.lookup.LookupIfProperty;
import io.vertx.core.json.JsonArray;

/**
 * Keycloak systems from the {@code kc_mcp_system} table: what a control plane writes
 * through {@link #save} and {@link #delete}, the server reads on every lookup (an indexed
 * read by alias; the admin client is cached per system by the server). A row's
 * {@code alias} is what {@link KeycloakSystem#name()} carries, its {@code name} a display
 * label. Active only with {@code kc-mcp.storage.enabled=true} and, like every repository,
 * {@code kc-mcp.dynamic-systems=true}. Client secrets and passwords are encrypted at rest
 * when {@code kc-mcp.storage.secret-key} is set.
 */
@ApplicationScoped
@LookupIfProperty(name = StorageConfigSourceFactory.ENABLED, stringValue = "true")
public class DatabaseKeycloakSystemRepository implements KeycloakSystemRepository {

    public static final String ID = "db-systems";

    private static final String ENABLED_IN_ORDER = "enabled = true order by createdAt, alias";

    private final StorageCrypto crypto;

    @Inject
    public DatabaseKeycloakSystemRepository(StorageCrypto crypto) {
        this.crypto = crypto;
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
    @Transactional
    public List<String> names() {
        return SystemEntity.<SystemEntity>list(ENABLED_IN_ORDER).stream().map(e -> e.alias).toList();
    }

    @Override
    @Transactional
    public Optional<KeycloakSystem> find(String alias) {
        return entity(alias).filter(e -> e.enabled).map(this::toSystem);
    }

    @Override
    @Transactional
    public List<KeycloakSystem> all() {
        return SystemEntity.<SystemEntity>list(ENABLED_IN_ORDER).stream().map(this::toSystem).toList();
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
     * Adds or replaces the system of an alias ({@link KeycloakSystem#name()}); the label
     * and the enabled flag of an existing row are kept. A replaced system is reconnected
     * by the server on its next use.
     */
    @Transactional
    public SystemEntity save(KeycloakSystem system) {
        return save(system, null);
    }

    /** @param name display label, {@code null} keeps the current one */
    @Transactional
    public SystemEntity save(KeycloakSystem system, String name) {
        long now = System.currentTimeMillis();
        SystemEntity e = entity(system.name()).orElse(null);
        if (e == null) {
            e = new SystemEntity();
            e.id = UUID.randomUUID().toString();
            e.alias = system.name();
            e.createdAt = now;
        }
        if (name != null) {
            e.name = name.isBlank() ? null : name.trim();
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
        return true;
    }

    /** Removes a system; false when unknown. Its signing keys stay in the vault. */
    @Transactional
    public boolean delete(String alias) {
        return SystemEntity.delete("alias = ?1", alias) > 0;
    }

    KeycloakSystem toSystem(SystemEntity e) {
        return new KeycloakSystem(e.alias, e.url, GrantType.parse(e.grantType), ClientAuth.parse(e.clientAuth),
                e.authRealm, optional(e.clientId), optional(crypto.reveal(e.clientSecret)), optional(e.username),
                optional(crypto.reveal(e.password)), optional(e.defaultRealm), realms(e.allowedRealms),
                optional(e.version), optional(e.issuer));
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

    private static Optional<String> optional(String value) {
        return value == null || value.isBlank() ? Optional.empty() : Optional.of(value);
    }
}
