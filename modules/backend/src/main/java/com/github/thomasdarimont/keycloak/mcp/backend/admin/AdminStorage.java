package com.github.thomasdarimont.keycloak.mcp.backend.admin;

import java.util.LinkedHashMap;
import java.util.Map;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;

import org.jboss.logging.Logger;

import com.github.thomasdarimont.keycloak.mcp.storage.StorageRekey;

/**
 * The database storage through the admin API ({@link AdminResource} is the HTTP face):
 * which encryption keys the stored values are under, and the re-encryption pass that
 * moves them to the current {@code kc-mcp.storage.secret-key} after a rotation.
 */
@ApplicationScoped
public class AdminStorage {

    private static final Logger LOG = Logger.getLogger(AdminStorage.class);

    @Inject
    Instance<StorageRekey> rekey;

    /** Encryption state and the key ids in use per table. */
    public Map<String, Object> status() {
        StorageRekey.Status status = storage().status();
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("encryption", status.encryption());
        out.put("currentKeyId", status.currentKeyId());
        out.put("previousKeys", status.previousKeys());
        out.put("keyIds", status.keyIds());
        return out;
    }

    /** Rewrites every value not under the current key; what it did. */
    public Map<String, Object> rekey() {
        StorageRekey storage = storage();
        StorageRekey.Result result = storage.rekey();
        if (result.currentKeyId() == null) {
            throw new AdminException(409, "encryption_disabled",
                    "kc-mcp.storage.secret-key is not set; there is no key to re-encrypt with.");
        }
        LOG.infof("Admin API: storage re-encrypted under the key %s (%d rows%s)", result.currentKeyId(),
                result.rewritten(),
                result.remaining().isEmpty() ? "" : ", still under other keys: " + result.remaining());
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("currentKeyId", result.currentKeyId());
        out.put("rewritten", Map.of("systems", result.systems(), "signingKeys", result.signingKeys(), "secrets",
                result.secrets(), "userSessions", result.userSessions()));
        out.put("remaining", result.remaining());
        return out;
    }

    private StorageRekey storage() {
        if (!rekey.isResolvable() || !rekey.get().enabled()) {
            throw new AdminException(503, "storage_disabled",
                    "The database storage is off: configure quarkus.datasource.jdbc.url.");
        }
        return rekey.get();
    }
}
