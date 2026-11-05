package com.github.thomasdarimont.keycloak.mcp.server.keycloak;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantLock;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import org.jboss.logging.Logger;

import com.github.thomasdarimont.keycloak.mcp.config.McpServerConfig;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeyVault;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystem;
import com.github.thomasdarimont.keycloak.mcp.keycloak.SigningKey;
import com.github.thomasdarimont.keycloak.mcp.server.spi.Extensions;
import com.github.thomasdarimont.keycloak.mcp.spi.Extension;
import com.github.thomasdarimont.keycloak.mcp.spi.ProviderConfig;

import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

/**
 * The {@code private_key_jwt} signing keys. A configured key ({@code kc-mcp.jwt.key-file}
 * or {@code keystore-file}) serves every system, as before; without one, each system gets
 * its own key pair from the {@link KeyVault} (a registered one, else the built-in
 * {@link FileKeyVault}), created on first use and published at
 * {@code /auth/keys/<system>/jwks.json}.
 */
@ApplicationScoped
public class SigningKeys {

    private static final Logger LOG = Logger.getLogger(SigningKeys.class);

    private final McpServerConfig config;
    private final KeyVault vault;
    private final ReentrantLock lock = new ReentrantLock();
    private volatile JwtSigner configured;
    private final Map<String, JwtSigner> perSystem = new ConcurrentHashMap<>();

    @Inject
    public SigningKeys(McpServerConfig config, Extensions extensions) {
        this(config, vault(config, extensions));
    }

    public SigningKeys(McpServerConfig config, KeyVault vault) {
        this.config = config;
        this.vault = vault;
    }

    /**
     * The registered vault with the lowest order, else the file vault under
     * {@code kc-mcp.keys-dir}.
     */
    static KeyVault vault(McpServerConfig config, Extensions extensions) {
        List<KeyVault> found = new ArrayList<>();
        for (KeyVault v : extensions.discover(KeyVault.class)) {
            if (ProviderConfig.forExtension(v.id(), config.spi()).getBoolean("enabled", true)) {
                found.add(v);
            }
        }
        found.sort(Comparator.comparingInt(Extension::order).thenComparing(Extension::id));
        if (!found.isEmpty()) {
            LOG.infof("Signing keys kept by %s", found.get(0).id());
            return found.get(0);
        }
        return new FileKeyVault(Extensions.resolve(config.keysDir()), config.jwt().algorithm());
    }

    /** Whether one configured key serves every system. */
    public boolean configuredKey() {
        return config.jwt().keyFile().isPresent() || config.jwt().keystoreFile().isPresent();
    }

    public int assertionLifespan() {
        return config.jwt().assertionLifespan();
    }

    public KeyVault vault() {
        return vault;
    }

    /**
     * The signer for a system: the configured key, else the system's own from the vault.
     */
    public JwtSigner signerFor(KeycloakSystem system) {
        if (configuredKey()) {
            return configured();
        }
        return perSystem.computeIfAbsent(system.name(), name -> {
            SigningKey key = vault.keyFor(name);
            LOG.infof("[%s] private_key_jwt key %s from %s", name,
                    key.keyId() == null ? "(thumbprint kid)" : key.keyId(), vault.id());
            return new JwtSigner(key.privateKey(), key.publicKey(), key.algorithm(), key.keyId());
        });
    }

    /**
     * The JWK Set of a system's key; empty when the system has no key yet and none is
     * configured.
     */
    public Optional<JsonObject> jwksFor(KeycloakSystem system) {
        if (configuredKey()) {
            return Optional.of(jwks(configured()));
        }
        return Optional.of(jwks(signerFor(system)));
    }

    /** The JWK Set of the configured key; empty when every system has its own. */
    public Optional<JsonObject> configuredJwks() {
        return configuredKey() ? Optional.of(jwks(configured())) : Optional.empty();
    }

    private JwtSigner configured() {
        JwtSigner s = configured;
        if (s != null) {
            return s;
        }
        lock.lock();
        try {
            if (configured == null) {
                configured = JwtSigner.fromConfig(config.jwt());
            }
            return configured;
        }
        finally {
            lock.unlock();
        }
    }

    private static JsonObject jwks(JwtSigner signer) {
        return new JsonObject().put("keys", new JsonArray().add(signer.jwk()));
    }
}
