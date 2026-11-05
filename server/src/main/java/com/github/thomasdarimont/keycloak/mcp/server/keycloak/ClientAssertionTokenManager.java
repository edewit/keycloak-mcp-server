package com.github.thomasdarimont.keycloak.mcp.server.keycloak;

import java.time.Instant;
import java.util.UUID;
import java.util.concurrent.locks.ReentrantLock;
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
    private final JwtSigner signer;
    private final int assertionLifespan;
    private final GrantType grantType;
    private final String username;
    private final String password;

    private final ReentrantLock lock = new ReentrantLock();
    private String token;
    private long expiresAt;

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

    private void grant() {
        long now = Instant.now().getEpochSecond();
        JsonObject claims = new JsonObject().put("iss", clientId)
            .put("sub", clientId)
            .put("aud", audience)
            .put("jti", UUID.randomUUID().toString())
            .put("iat", now)
            .put("nbf", now)
            .put("exp", now + assertionLifespan);
        String assertion = signer.sign(claims);
        Form form = new Form().param("grant_type", grantType.oauthValue())
            .param("client_id", clientId)
            .param("client_assertion_type", ASSERTION_TYPE)
            .param("client_assertion", assertion);
        if (grantType == GrantType.PASSWORD) {
            form.param("username", username).param("password", password);
        }
        try (Response response = client.target(tokenEndpoint)
            .request(MediaType.APPLICATION_JSON_TYPE)
            .post(Entity.form(form))) {
            String body = response.hasEntity() ? response.readEntity(String.class) : "";
            if (response.getStatus() != 200) {
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

    @Override
    public void close() {
        client.close();
    }
}
