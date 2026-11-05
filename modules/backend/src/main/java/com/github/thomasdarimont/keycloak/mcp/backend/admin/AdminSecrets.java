package com.github.thomasdarimont.keycloak.mcp.backend.admin;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Pattern;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import org.jboss.logging.Logger;

import com.github.thomasdarimont.keycloak.mcp.backend.keycloak.DefaultKeycloakSystems;
import com.github.thomasdarimont.keycloak.mcp.backend.keycloak.SigningKeys;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeyVault;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystem;

/**
 * The secrets of the {@link KeyVault} through the admin API ({@link AdminResource} is the
 * HTTP face): a control plane stores a tenant's client secret or admin password under a
 * name and registers the system with {@code "clientSecret": "vault:<name>"}, so the value
 * never appears in a system's row or representation. Values go in and are never read
 * back; the API lists names and which systems use them. Storing needs a vault that
 * {@link KeyVault#supportsSecretStorage() supports it} (the database vault); the file
 * vault and a secrets manager stay read-only and answer 409. A secret in use cannot be
 * removed; a replaced value reaches its systems at their next connection.
 */
@ApplicationScoped
public class AdminSecrets {

    private static final Logger LOG = Logger.getLogger(AdminSecrets.class);

    /** Path-like names ({@code acme/client-secret}); no blanks, no {@code ..}. */
    static final Pattern NAME = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._/-]{0,254}");

    @Inject
    DefaultKeycloakSystems systems;
    @Inject
    SigningKeys keys;

    /** The names the vault holds with the systems referencing each, never a value. */
    public Map<String, Object> list() {
        KeyVault vault = keys.vault();
        List<Map<String, Object>> out = new ArrayList<>();
        for (String name : vault.secretNames()) {
            out.add(represent(name));
        }
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("vault", vault.id());
        result.put("writable", vault.supportsSecretStorage());
        result.put("secrets", out);
        return result;
    }

    public Map<String, Object> get(String name) {
        validName(name);
        if (keys.vault().findSecret(name).isEmpty()) {
            throw unknown(name);
        }
        return represent(name);
    }

    /**
     * Stores or replaces a secret.
     *
     * @param body {@code {"value": "..."}}
     */
    public Saved put(String name, Map<String, Object> body) {
        validName(name);
        KeyVault vault = writableVault();
        Object value = body == null ? null : body.get("value");
        if (!(value instanceof String s) || s.isBlank()) {
            throw new AdminException(400, "invalid_secret", "A JSON object {\"value\": \"...\"} is expected.");
        }
        boolean replaced = vault.findSecret(name).isPresent();
        vault.putSecret(name, s);
        List<String> users = usedBy(name);
        users.forEach(systems::forget);
        LOG.infof("Admin API: secret '%s' %s in '%s'%s", name, replaced ? "replaced" : "stored", vault.id(),
                users.isEmpty() ? "" : ", used by " + users);
        return new Saved(represent(name), replaced);
    }

    /** Removes a secret no system refers to. */
    public void delete(String name) {
        validName(name);
        KeyVault vault = writableVault();
        if (vault.findSecret(name).isEmpty()) {
            throw unknown(name);
        }
        List<String> users = usedBy(name);
        if (!users.isEmpty()) {
            throw new AdminException(409, "secret_in_use",
                    "The secret '" + name + "' is referenced by " + users + "; change or remove those systems first.");
        }
        vault.deleteSecret(name);
        LOG.infof("Admin API: secret '%s' removed from '%s'", name, vault.id());
    }

    /**
     * The aliases of the systems whose client secret or password is {@code vault:<name>}.
     */
    List<String> usedBy(String name) {
        List<String> out = new ArrayList<>();
        for (KeycloakSystem s : systems.repository().all()) {
            for (Optional<String> value : List.of(s.clientSecret(), s.password())) {
                if (value.isPresent() && KeycloakSystem.isVaultRef(value.get())
                        && name.equals(KeycloakSystem.vaultRefName(value.get())) && !out.contains(s.name())) {
                    out.add(s.name());
                }
            }
        }
        return out.stream().sorted().toList();
    }

    private Map<String, Object> represent(String name) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("name", name);
        out.put("reference", KeycloakSystem.VAULT_REF + name);
        out.put("vault", keys.vault().id());
        out.put("usedBy", usedBy(name));
        return out;
    }

    private KeyVault writableVault() {
        KeyVault vault = keys.vault();
        if (!vault.supportsSecretStorage()) {
            throw new AdminException(409, "vault_read_only",
                    "KeyVault '" + vault.id()
                            + "' does not store secrets; provision them there, or configure the database storage"
                            + " (quarkus.datasource.jdbc.url), whose vault does.");
        }
        return vault;
    }

    private static void validName(String name) {
        if (name == null || !NAME.matcher(name).matches() || name.contains("..") || name.contains("//")) {
            throw new AdminException(400, "invalid_secret_name", "The name must match " + NAME.pattern()
                    + " (letters, digits, '.', '_', '-', '/'; e.g. acme/client-secret).");
        }
    }

    private static AdminException unknown(String name) {
        return new AdminException(404, "unknown_secret", "No secret named '" + name + "' in the vault.");
    }
}
