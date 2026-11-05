package com.github.thomasdarimont.keycloak.mcp.backend.keycloak;

import java.util.Optional;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;

import org.jboss.logging.Logger;

import com.github.thomasdarimont.keycloak.mcp.config.ClientAuth;
import com.github.thomasdarimont.keycloak.mcp.config.McpServerConfig;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakAdmin;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystems;

import io.vertx.core.http.HttpMethod;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;

/**
 * Serves the {@code private_key_jwt} public keys as JWK Sets so the Keycloak client
 * representing this server can use "JWKS URL" instead of an imported certificate:
 * {@code /auth/keys/<system>/jwks.json} per system (the configured key, or the system's
 * own from the vault), and {@code kc-mcp.jwt.jwks-path} (default
 * {@code /.well-known/jwks.json}) for the configured key, else the default system's. Off
 * with {@code kc-mcp.jwt.jwks-enabled=false}.
 */
@ApplicationScoped
public class JwksEndpoint {

    private static final Logger LOG = Logger.getLogger(JwksEndpoint.class);

    public static final String SYSTEM_PATH = "/auth/keys/:system/jwks.json";

    @Inject
    McpServerConfig config;
    @Inject
    SigningKeys keys;
    @Inject
    KeycloakSystems systems;

    void register(@Observes Router router) {
        if (!config.jwt().jwksEnabled()) {
            return;
        }
        // blocking: a system repository or key vault may go to a database
        router.route(HttpMethod.GET, config.jwt().jwksPath()).blockingHandler(ctx -> serve(ctx, legacy()));
        router.route(HttpMethod.GET, SYSTEM_PATH)
            .blockingHandler(ctx -> serve(ctx, forSystem(ctx.pathParam("system"))));
        LOG.infof("JWKS served at %s and %s", config.jwt().jwksPath(), SYSTEM_PATH);
    }

    /** The configured key, else the default system's own key. */
    private Optional<JsonObject> legacy() {
        Optional<JsonObject> configured = keys.configuredJwks();
        if (configured.isPresent()) {
            return configured;
        }
        return systems.defaultName().flatMap(this::forSystem);
    }

    private Optional<JsonObject> forSystem(String name) {
        Optional<KeycloakAdmin> admin = systems.find(name);
        if (admin.isEmpty() || admin.get().system().clientAuth() != ClientAuth.PRIVATE_KEY_JWT) {
            return Optional.empty();
        }
        return keys.jwksFor(admin.get().system());
    }

    private static void serve(RoutingContext ctx, Optional<JsonObject> jwks) {
        try {
            if (jwks.isEmpty()) {
                ctx.response()
                    .setStatusCode(404)
                    .putHeader("Content-Type", "application/json")
                    .end("{\"error\":\"no_jwks\",\"message\":\"No private_key_jwt key for this system.\"}");
                return;
            }
            ctx.response()
                .putHeader("Content-Type", "application/json")
                .putHeader("Cache-Control", "public, max-age=300")
                .end(jwks.get().encode());
        }
        catch (RuntimeException e) {
            LOG.errorf("Cannot serve JWKS: %s", e.getMessage());
            ctx.response()
                .setStatusCode(500)
                .putHeader("Content-Type", "application/json")
                .end("{\"error\":\"jwks_unavailable\",\"message\":\"" + e.getMessage().replace('"', '\'') + "\"}");
        }
    }
}
