package org.keycloak.mcp.keycloak;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;

import org.jboss.logging.Logger;
import org.keycloak.mcp.config.McpServerConfig;

import io.vertx.core.http.HttpMethod;
import io.vertx.ext.web.Router;

/**
 * Serves the public key of the {@code private_key_jwt} client as a JWK Set (default
 * {@code /.well-known/jwks.json}) so the Keycloak client representing this server can use
 * "JWKS URL" instead of an imported certificate. Only registered when client auth is
 * {@code private_key_jwt} and {@code kc-mcp.jwt.jwks-enabled} is true.
 */
@ApplicationScoped
public class JwksEndpoint {

    private static final Logger LOG = Logger.getLogger(JwksEndpoint.class);

    @Inject
    McpServerConfig config;
    @Inject
    JwtKeyMaterial keys;

    void register(@Observes Router router) {
        if (!keys.enabled() || !config.jwt().jwksEnabled()) {
            return;
        }
        String path = config.jwt().jwksPath();
        router.route(HttpMethod.GET, path).handler(ctx -> {
            try {
                String body = keys.jwks().encode();
                ctx.response()
                    .putHeader("Content-Type", "application/json")
                    .putHeader("Cache-Control", "public, max-age=300")
                    .end(body);
            }
            catch (RuntimeException e) {
                LOG.errorf("Cannot serve JWKS: %s", e.getMessage());
                ctx.response()
                    .setStatusCode(500)
                    .putHeader("Content-Type", "application/json")
                    .end("{\"error\":\"jwks_unavailable\",\"message\":\"" + e.getMessage().replace('"', '\'') + "\"}");
            }
        });
        LOG.infof("JWKS of the private_key_jwt key served at %s", path);
    }
}
