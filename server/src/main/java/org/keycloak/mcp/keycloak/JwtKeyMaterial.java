package org.keycloak.mcp.keycloak;

import java.util.concurrent.locks.ReentrantLock;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import org.keycloak.mcp.config.ClientAuth;
import org.keycloak.mcp.config.McpServerConfig;

import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

/**
 * The {@code private_key_jwt} signing key, loaded once and shared by the token manager
 * and the JWKS endpoint.
 */
@ApplicationScoped
public class JwtKeyMaterial {

    private final McpServerConfig config;
    private final ReentrantLock lock = new ReentrantLock();
    private volatile JwtSigner signer;

    @Inject
    public JwtKeyMaterial(McpServerConfig config) {
        this.config = config;
    }

    /** True when any configured system authenticates with a JWT. */
    public boolean enabled() {
        return DefaultKeycloakSystems.resolve(config)
            .stream()
            .anyMatch(s -> s.clientAuth() == ClientAuth.PRIVATE_KEY_JWT);
    }

    public int assertionLifespan() {
        return config.jwt().assertionLifespan();
    }

    public JwtSigner signer() {
        JwtSigner s = signer;
        if (s != null) {
            return s;
        }
        lock.lock();
        try {
            if (signer == null) {
                signer = JwtSigner.fromConfig(config.jwt());
            }
            return signer;
        }
        finally {
            lock.unlock();
        }
    }

    /** {@code {"keys":[...]}} with the current public key. */
    public JsonObject jwks() {
        return new JsonObject().put("keys", new JsonArray().add(signer().jwk()));
    }
}
