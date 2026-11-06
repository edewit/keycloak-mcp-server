package com.github.thomasdarimont.keycloak.mcp.backend.keycloak;

import java.time.Instant;
import java.util.UUID;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Supplier;
import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.Form;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.jboss.logging.Logger;

import com.github.thomasdarimont.keycloak.mcp.catalog.ToolException;
import com.github.thomasdarimont.keycloak.mcp.config.GrantType;

import io.vertx.core.json.JsonObject;

/**
 * Fetches and caches access tokens for a client authenticating with a signed JWT (RFC
 * 7523 / OIDC {@code private_key_jwt}); works with the {@code client_credentials} and the
 * {@code password} grant.
 */
public class ClientAssertionTokenManager implements AutoCloseable {

    private static final Logger LOG = Logger.getLogger(ClientAssertionTokenManager.class);
    private static final String ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
    private static final long MIN_VALIDITY_SECONDS = 30;

    private final Client client;
    private final String tokenEndpoint;
    private final String audience;
    private final String clientId;
    private final Supplier<JwtSigner> signer;
    private final int assertionLifespan;
    private final GrantType grantType;
    private final String username;
    private final String password;

    private final ReentrantLock lock = new ReentrantLock();
    private String token;
    private long expiresAt;
    private String scope;
    private boolean scopeRefused;
    private Runnable onScopeRefused = () -> {
    };

    public ClientAssertionTokenManager(Client client, String serverUrl, String realm, String clientId, JwtSigner signer,
            int assertionLifespan, GrantType grantType, String username, String password) {
        this(client, serverUrl, realm, null, clientId, signer, assertionLifespan, grantType, username, password);
    }

    /**
     * @param audience the {@code aud} of the assertions, Keycloak's issuer URL of the
     * realm; {@code null} derives it from the server URL
     */
    public ClientAssertionTokenManager(Client client, String serverUrl, String realm, String audience, String clientId,
            JwtSigner signer, int assertionLifespan, GrantType grantType, String username, String password) {
        this(client, serverUrl, realm, audience, clientId, () -> signer, assertionLifespan, grantType, username,
                password);
    }

    /**
     * @param signer asked for the signer on every token request, so a key rotated in the
     * vault (by this or another instance) is used from the next request on
     */
    public ClientAssertionTokenManager(Client client, String serverUrl, String realm, String audience, String clientId,
            Supplier<JwtSigner> signer, int assertionLifespan, GrantType grantType, String username, String password) {
        this.client = client;
        String base = serverUrl.endsWith("/") ? serverUrl.substring(0, serverUrl.length() - 1) : serverUrl;
        this.tokenEndpoint = base + "/realms/" + realm + "/protocol/openid-connect/token";
        this.audience = audience != null && !audience.isBlank() ? audience : base + "/realms/" + realm;
        this.clientId = clientId;
        this.signer = signer;
        this.assertionLifespan = assertionLifespan;
        this.grantType = grantType;
        this.username = username;
        this.password = password;
    }

    /**
     * Asks for a scope with every token request (Keycloak 26.8.2+: {@code kc-admin-api},
     * whose audience the Admin API demands). A server that answers {@code invalid_scope}
     * is asked again without it and the scope is dropped from then on, so older Keycloak
     * versions and clients without the scope keep working.
     */
    /** Called once when the server refuses the scope (metrics). */
    public ClientAssertionTokenManager onScopeRefused(Runnable listener) {
        this.onScopeRefused = listener == null ? () -> {
        } : listener;
        return this;
    }

    public ClientAssertionTokenManager scope(String scope) {
        this.scope = scope == null || scope.isBlank() ? null : scope.trim();
        return this;
    }

    /**
     * The scope requested with tokens, {@code null} when none or after it was refused.
     */
    public String scope() {
        return scopeRefused ? null : scope;
    }

    /**
     * Token endpoint derived from the server URL (context paths such as {@code /auth} are
     * preserved).
     */
    public String tokenEndpoint() {
        return tokenEndpoint;
    }

    public String audience() {
        return audience;
    }

    public String accessToken() {
        lock.lock();
        try {
            long now = Instant.now().getEpochSecond();
            if (token == null || now + MIN_VALIDITY_SECONDS >= expiresAt) {
                grant();
            }
            return token;
        }
        finally {
            lock.unlock();
        }
    }

    public void invalidate() {
        lock.lock();
        try {
            token = null;
            expiresAt = 0;
        }
        finally {
            lock.unlock();
        }
    }

    /**
     * A signed client assertion (RFC 7523): {@code iss} and {@code sub} the client,
     * {@code aud} the realm's issuer, valid for {@code lifespan} seconds from now.
     */
    public static String clientAssertion(String clientId, String audience, JwtSigner signer, int lifespan) {
        long now = Instant.now().getEpochSecond();
        JsonObject claims = new JsonObject().put("iss", clientId)
            .put("sub", clientId)
            .put("aud", audience)
            .put("jti", UUID.randomUUID().toString())
            .put("iat", now)
            .put("nbf", now)
            .put("exp", now + lifespan);
        return signer.sign(claims);
    }

    private void grant() {
        long now = Instant.now().getEpochSecond();
        String assertion = clientAssertion(clientId, audience, signer.get(), assertionLifespan);
        Form form = new Form().param("grant_type", grantType.oauthValue())
            .param("client_id", clientId)
            .param("client_assertion_type", ASSERTION_TYPE)
            .param("client_assertion", assertion);
        if (grantType == GrantType.PASSWORD) {
            form.param("username", username).param("password", password);
        }
        boolean withScope = scope != null && !scopeRefused;
        if (withScope) {
            form.param("scope", scope);
        }
        try (Response response = client.target(tokenEndpoint)
            .request(MediaType.APPLICATION_JSON_TYPE)
            .post(Entity.form(form))) {
            String body = response.hasEntity() ? response.readEntity(String.class) : "";
            if (response.getStatus() != 200) {
                if (withScope && isInvalidScope(response.getStatus(), body)) {
                    LOG.infof("Keycloak at %s does not know the scope '%s' (%s); requesting tokens without it",
                            tokenEndpoint, scope, body.replaceAll("\\s+", " ").trim());
                    scopeRefused = true;
                    onScopeRefused.run();
                    grant();
                    return;
                }
                LOG.warnf("private_key_jwt token request failed: HTTP %d %s", response.getStatus(), body);
                throw new ToolException("unauthorized",
                        "Keycloak rejected the client assertion (HTTP " + response.getStatus() + "): " + body);
            }
            JsonObject json = new JsonObject(body);
            token = json.getString("access_token");
            long expiresIn = json.getLong("expires_in", 60L);
            expiresAt = now + expiresIn;
        }
    }

    /**
     * Whether a token endpoint answer refuses the requested scope (RFC 6749
     * {@code invalid_scope}).
     */
    static boolean isInvalidScope(int status, String body) {
        return status == 400 && body != null && body.contains("invalid_scope");
    }

    @Override
    public void close() {
        client.close();
    }
}
