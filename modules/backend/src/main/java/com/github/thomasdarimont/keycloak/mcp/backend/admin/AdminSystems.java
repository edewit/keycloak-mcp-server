package com.github.thomasdarimont.keycloak.mcp.backend.admin;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Pattern;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;

import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;

import com.github.thomasdarimont.keycloak.mcp.backend.http.EntryRoutes;
import com.github.thomasdarimont.keycloak.mcp.backend.keycloak.DefaultKeycloakSystems;
import com.github.thomasdarimont.keycloak.mcp.backend.keycloak.FileSystemKeycloakSystemRepository;
import com.github.thomasdarimont.keycloak.mcp.backend.keycloak.Jwks;
import com.github.thomasdarimont.keycloak.mcp.backend.keycloak.JwksEndpoint;
import com.github.thomasdarimont.keycloak.mcp.backend.keycloak.SigningKeys;
import com.github.thomasdarimont.keycloak.mcp.config.ClientAuth;
import com.github.thomasdarimont.keycloak.mcp.config.GrantType;
import com.github.thomasdarimont.keycloak.mcp.config.McpServerConfig;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeyVault;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystem;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystemRepository;
import com.github.thomasdarimont.keycloak.mcp.keycloak.MutableKeycloakSystemRepository;
import com.github.thomasdarimont.keycloak.mcp.keycloak.SigningKey;

import io.quarkus.runtime.StartupEvent;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

/**
 * What the admin API does ({@link AdminResource} is the HTTP face): registers a Keycloak
 * system at runtime the way a control plane would. Systems go into the first
 * {@link MutableKeycloakSystemRepository} (the database storage); a
 * {@code private_key_jwt} system gets its key from the {@link KeyVault}: an existing one
 * (provisioned there by other means, {@code "signingKey": "existing"}) or a freshly
 * generated one ({@code "generate"}, vaults that create keys); without the field an
 * existing key is used and one is generated when there is none. {@code vault:<name>}
 * client secrets and passwords must resolve against the vault's secrets. The
 * representation carries the system's JWKS URL, which the Keycloak client representing
 * this server points at, and never a secret. Requests and representations are plain maps
 * and lists, JSON on the wire.
 */
@ApplicationScoped
public class AdminSystems {

    private static final Logger LOG = Logger.getLogger(AdminSystems.class);

    static final Pattern ALIAS = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._-]{0,127}");

    @Inject
    McpServerConfig config;
    @Inject
    DefaultKeycloakSystems systems;
    @Inject
    SigningKeys keys;
    @ConfigProperty(name = "quarkus.mcp.server.root-path", defaultValue = "/mcp")
    String rootPath;

    void onStart(@Observes StartupEvent event) {
        if (!config.admin().enabled()) {
            return;
        }
        boolean token = config.admin().token().filter(t -> !t.isBlank()).isPresent();
        Optional<String> issuer = config.admin().issuer().filter(t -> !t.isBlank());
        if (!token && issuer.isEmpty()) {
            throw new IllegalStateException(
                    "kc-mcp.admin.enabled=true needs kc-mcp.admin.token or kc-mcp.admin.issuer");
        }
        String how = issuer.map(i -> "access tokens of " + i + " with role " + config.admin().role()).orElse("");
        how = token ? (how.isEmpty() ? "static token" : "static token or " + how) : how;
        LOG.infof("Admin API at %s/systems (%s), systems go to %s%s", AdminResource.PATH, how,
                systems.mutableRepository().map(KeycloakSystemRepository::id).orElse("<no mutable repository>"),
                config.admin().allowNewSystems() ? "" : ", registration of new systems closed");
    }

    /** Every known system, static ones included. */
    public Map<String, Object> list(String publicBase) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (String name : systems.names()) {
            systems.repository().find(name).ifPresent(s -> out.add(represent(s, publicBase)));
        }
        return Map.of("systems", out);
    }

    public Map<String, Object> get(String alias, String publicBase) {
        return represent(known(alias), publicBase);
    }

    /**
     * Registers or replaces a system.
     *
     * @param body the systems file fields plus {@code signingKey}
     * @param aliasFromPath the alias when it is not in the body
     * @return the representation and whether the system existed before
     */
    public Saved save(Map<String, Object> body, String aliasFromPath, String publicBase) {
        MutableKeycloakSystemRepository target = systems.mutableRepository()
            .orElseThrow(() -> new AdminException(503, "no_mutable_repository",
                    "No repository to register systems in: configure the database storage"
                            + " (quarkus.datasource.jdbc.url) and kc-mcp.dynamic-systems=true."));
        if (body == null) {
            throw new AdminException(400, "invalid_system", "A JSON object with at least 'url' is expected.");
        }
        KeycloakSystem system;
        try {
            system = FileSystemKeycloakSystemRepository.parseSystem(new JsonObject(body), aliasFromPath);
        }
        catch (IllegalArgumentException | ClassCastException e) {
            throw new AdminException(400, "invalid_system", e.getMessage());
        }
        if (!ALIAS.matcher(system.name()).matches()) {
            throw new AdminException(400, "invalid_alias", "The alias must match " + ALIAS.pattern() + ".");
        }
        if (!system.url().startsWith("http://") && !system.url().startsWith("https://")) {
            throw new AdminException(400, "invalid_url", "The url must be http(s).");
        }
        if (system.grantType() != GrantType.CLIENT_CREDENTIALS) {
            throw new AdminException(400, "grant_not_supported",
                    "Registered systems authenticate as service clients:"
                            + " grantType must be client_credentials (private_key_jwt or client_secret). The "
                            + system.grantType().oauthValue()
                            + " grant is deprecated by OAuth 2.1 and only the static configuration supports it.");
        }
        if (!systems.allowedHosts().permits(system.url())) {
            throw new AdminException(400, "host_not_allowed", "The url " + system.url()
                    + " is not covered by kc-mcp.allowed-hosts " + systems.allowedHosts().patterns() + ".");
        }
        systems.dynamicHostProblem(system.url()).ifPresent(why -> {
            throw new AdminException(400, "private_host", why);
        });
        Optional<KeycloakSystemRepository> owner = systems.repositoryOf(system.name());
        if (owner.isEmpty() && !config.admin().allowNewSystems()) {
            throw new AdminException(403, "registration_closed", "The admin API registers no new systems"
                    + " (kc-mcp.admin.allow-new-systems=false); known systems can still be changed.");
        }
        if (owner.isPresent() && !(owner.get() instanceof MutableKeycloakSystemRepository)) {
            throw new AdminException(409, "system_configured", "'" + system.name() + "' is defined by the repository '"
                    + owner.get().id() + "', which the admin API cannot change.");
        }
        checkSecrets(system);
        if (system.clientAuth() == ClientAuth.PRIVATE_KEY_JWT && !keys.configuredKey()) {
            Object mode = body.get("signingKey");
            provideKey(system.name(), mode == null ? null : String.valueOf(mode));
        }
        KeycloakSystem stored = target.save(system);
        systems.forget(system.name());
        LOG.infof("Admin API: system '%s' at %s %s in '%s'", system.name(), system.url(),
                owner.isPresent() ? "replaced" : "registered", target.id());
        return new Saved(represent(stored, publicBase), owner.isPresent());
    }

    private void provideKey(String alias, String signingKey) {
        KeyVault vault = keys.vault();
        Optional<SigningKey> existing = vault.findSigningKey(alias);
        String mode = signingKey == null ? (existing.isPresent() ? "existing" : "generate")
                : signingKey.trim().toLowerCase(Locale.ROOT);
        switch (mode) {
            case "existing" -> {
                if (existing.isEmpty()) {
                    throw new AdminException(400, "no_signing_key",
                            "KeyVault '" + vault.id() + "' has no private_key_jwt key for '" + alias
                                    + "'; provision one there or ask for \"signingKey\": \"generate\".");
                }
            }
            case "generate" -> {
                if (existing.isPresent()) {
                    throw new AdminException(409, "signing_key_exists",
                            "'" + alias + "' already has a key in KeyVault '" + vault.id() + "'; rotate it with POST "
                                    + AdminResource.PATH + "/systems/" + alias
                                    + "/signing-key or register with \"signingKey\": \"existing\".");
                }
                if (!vault.supportsKeyCreation()) {
                    throw new AdminException(400, "vault_read_only", "KeyVault '" + vault.id()
                            + "' cannot create keys; provision one for '" + alias + "' there.");
                }
                vault.createSigningKey(alias);
            }
            default -> throw new AdminException(400, "invalid_signing_key",
                    "signingKey must be \"existing\" or \"generate\".");
        }
    }

    /** A {@code vault:} reference the vault does not resolve is refused. */
    private void checkSecrets(KeycloakSystem system) {
        for (Optional<String> value : List.of(system.clientSecret(), system.password())) {
            if (value.isPresent() && KeycloakSystem.isVaultRef(value.get())) {
                String name = KeycloakSystem.vaultRefName(value.get());
                if (keys.vault().findSecret(name).isEmpty()) {
                    throw new AdminException(400, "unknown_secret",
                            "KeyVault '" + keys.vault().id() + "' has no secret named '" + name + "'.");
                }
            }
        }
    }

    /** Removes a registered system; its keys stay in the vault. */
    public void delete(String alias) {
        KeycloakSystemRepository owner = systems.repositoryOf(alias)
            .orElseThrow(() -> new AdminException(404, "unknown_system", "No Keycloak system named '" + alias + "'."));
        if (!(owner instanceof MutableKeycloakSystemRepository mutable)) {
            throw new AdminException(409, "system_configured", "'" + alias + "' is defined by the repository '"
                    + owner.id() + "', which the admin API cannot change.");
        }
        mutable.delete(alias);
        systems.forget(alias);
        LOG.infof("Admin API: system '%s' removed from '%s'", alias, mutable.id());
    }

    /** Creates a new key for the system; the previous one is retired. */
    public Map<String, Object> rotate(String alias, String publicBase) {
        KeycloakSystem system = known(alias);
        if (system.clientAuth() != ClientAuth.PRIVATE_KEY_JWT) {
            throw new AdminException(409, "no_private_key_jwt",
                    "'" + alias + "' does not authenticate with private_key_jwt.");
        }
        try {
            keys.rotate(alias);
        }
        catch (UnsupportedOperationException e) {
            throw new AdminException(409, "vault_read_only", e.getMessage());
        }
        return represent(system, publicBase);
    }

    private KeycloakSystem known(String alias) {
        return systems.repository()
            .find(alias)
            .orElseThrow(() -> new AdminException(404, "unknown_system", "No Keycloak system named '" + alias + "'."));
    }

    /**
     * The system without its secrets, with its key's kid and JWKS URL, its entries and,
     * from repositories that keep them, {@code createdAt} / {@code updatedAt} (ISO-8601).
     */
    Map<String, Object> represent(KeycloakSystem s, String publicBase) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("alias", s.name());
        s.displayName().ifPresent(v -> out.put("displayName", v));
        s.description().ifPresent(v -> out.put("description", v));
        out.put("url", s.url());
        s.issuer().ifPresent(v -> out.put("issuer", v));
        out.put("authRealm", s.authRealm());
        out.put("grantType", s.grantType().oauthValue());
        out.put("clientAuth", s.clientAuth().name().toLowerCase(Locale.ROOT));
        s.clientId().ifPresent(v -> out.put("clientId", v));
        s.clientSecret().ifPresent(v -> out.put("clientSecret", KeycloakSystem.isVaultRef(v) ? v : "***"));
        s.username().ifPresent(v -> out.put("username", v));
        s.password().ifPresent(v -> out.put("password", KeycloakSystem.isVaultRef(v) ? v : "***"));
        s.defaultRealm().ifPresent(v -> out.put("defaultRealm", v));
        out.put("allowedRealms", s.allowedRealms().stream().sorted().toList());
        s.version().ifPresent(v -> out.put("version", v));
        systems.repositoryOf(s.name()).ifPresent(r -> {
            out.put("source", r.id());
            r.timestamps(s.name()).ifPresent(t -> {
                out.put("createdAt", t.createdAt().toString());
                out.put("updatedAt", t.updatedAt().toString());
            });
        });
        if (s.clientAuth() == ClientAuth.PRIVATE_KEY_JWT) {
            Map<String, Object> key = new LinkedHashMap<>();
            String path = JwksEndpoint.SYSTEM_PATH.replace(":system", s.name());
            if (keys.configuredKey()) {
                key.put("configured", true);
                key.put("kid", keys.configuredJwks().map(AdminSystems::kid).orElse(null));
            }
            else {
                keys.currentKey(s.name()).ifPresent(k -> {
                    key.put("algorithm", k.algorithm());
                    key.put("kid", Jwks.jwk(k.publicKey(), k.algorithm(), k.keyId()).getString("kid"));
                });
                key.put("vault", keys.vault().id());
            }
            key.put("jwksPath", path);
            key.put("jwksUrl", publicBase + path);
            out.put("signingKey", key);
        }
        String root = EntryRoutes.root(rootPath) + "/" + EntryRoutes.SEGMENT + "/" + s.name();
        List<String> entries = new ArrayList<>();
        entries.add(root);
        s.defaultRealm().ifPresent(r -> entries.add(root + "/" + r));
        s.allowedRealms()
            .stream()
            .sorted()
            .filter(r -> !s.defaultRealm().orElse("").equals(r))
            .forEach(r -> entries.add(root + "/" + r));
        out.put("entries", entries);
        return out;
    }

    private static String kid(JsonObject jwks) {
        JsonArray keys = jwks.getJsonArray("keys");
        return keys == null || keys.isEmpty() ? null : keys.getJsonObject(0).getString("kid");
    }
}
