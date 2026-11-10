package com.github.thomasdarimont.keycloak.mcp.backend.oauth;

import java.net.URI;
import java.time.Clock;
import java.time.Instant;
import java.util.concurrent.locks.ReentrantLock;
import jakarta.ws.rs.ProcessingException;
import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.client.Invocation;
import jakarta.ws.rs.core.Form;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import com.github.thomasdarimont.keycloak.mcp.oauth.ClientAuthenticator;
import com.github.thomasdarimont.keycloak.mcp.oauth.TokenRequest;

import io.vertx.core.json.DecodeException;
import io.vertx.core.json.JsonObject;

/**
 * Access tokens from any OAuth authorization server through the
 * {@code client_credentials} grant, the client authenticating with a
 * {@link ClientAuthenticator}. One token is kept and replaced shortly before its
 * {@code expires_in} runs out, or when the resource server refused it
 * ({@link #renew(String)}).
 */
public class ClientCredentialsTokens {

    /** The token endpoint did not hand out a token. */
    public static class TokenException extends RuntimeException {
        TokenException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    private record Token(String value, Instant expires) {
    }

    /** A token is renewed this long before its {@code expires_in} runs out. */
    static final long EXPIRY_MARGIN_SECONDS = 30;

    private final Client http;
    private final URI tokenEndpoint;
    private final ClientAuthenticator authenticator;
    private final String scope;
    private final Clock clock;
    private final ReentrantLock lock = new ReentrantLock();
    private volatile Token token;

    /** @param scope requested scope, {@code null} for none */
    public ClientCredentialsTokens(Client http, URI tokenEndpoint, ClientAuthenticator authenticator, String scope,
            Clock clock) {
        this.http = http;
        this.tokenEndpoint = tokenEndpoint;
        this.authenticator = authenticator;
        this.scope = scope;
        this.clock = clock;
    }

    /** The current token, a new one when it ran out. */
    public String accessToken() {
        Token t = token;
        if (valid(t)) {
            return t.value();
        }
        return renew(null);
    }

    /**
     * A new token unless another call already replaced {@code rejected}, the one the
     * resource server refused; {@code null} renews an expired token only.
     */
    public String renew(String rejected) {
        lock.lock();
        try {
            Token t = token;
            if (valid(t) && !t.value().equals(rejected)) {
                return t.value();
            }
            Token fresh = fetch();
            token = fresh;
            return fresh.value();
        }
        finally {
            lock.unlock();
        }
    }

    private boolean valid(Token t) {
        return t != null && t.expires().isAfter(clock.instant());
    }

    private Token fetch() {
        TokenRequest request = new TokenRequest(tokenEndpoint).param("grant_type", "client_credentials")
            .param("scope", scope);
        authenticator.authenticate(request);
        Form form = new Form();
        request.form().forEach(form::param);
        Invocation.Builder b = http.target(tokenEndpoint).request(MediaType.APPLICATION_JSON_TYPE);
        request.headers().forEach(b::header);
        try (Response r = b.post(Entity.form(form))) {
            String body = r.hasEntity() ? r.readEntity(String.class) : "";
            if (r.getStatus() != 200) {
                throw new TokenException(tokenEndpoint + " answered HTTP " + r.getStatus() + " " + error(body), null);
            }
            JsonObject json = new JsonObject(body);
            String value = json.getString("access_token");
            if (value == null || value.isBlank()) {
                throw new TokenException(tokenEndpoint + " answered without an access_token", null);
            }
            long expiresIn = json.getLong("expires_in", 60L);
            return new Token(value, clock.instant().plusSeconds(Math.max(1, expiresIn - EXPIRY_MARGIN_SECONDS)));
        }
        catch (ProcessingException | DecodeException | ClassCastException e) {
            throw new TokenException("no token from " + tokenEndpoint + ": " + e.getMessage(), e);
        }
    }

    /** The OAuth error code of an answer, never its whole body. */
    private static String error(String body) {
        try {
            String e = new JsonObject(body).getString("error");
            return e == null ? "" : e;
        }
        catch (RuntimeException ignored) {
            return "";
        }
    }
}
