package com.github.thomasdarimont.keycloak.mcp.backend.ui;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Optional;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import org.jboss.logging.Logger;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.thomasdarimont.keycloak.mcp.web.UserSession;
import com.github.thomasdarimont.keycloak.mcp.web.UserSessionStore;

/**
 * Asks the identity provider whether a browser session is still alive, by redeeming its
 * refresh token: Keycloak refuses ({@code invalid_grant}) once the SSO session ended
 * (logout in another application or the account console, an administrator, the idle
 * timeout), and a success both proves the session and counts as activity there, so the
 * idle timeout moves. The new tokens replace the stored ones under the same session id,
 * and the caller re-sends the cookie with a lifetime that fits the new ID token; an ended
 * session loses its row. This is activity tracking driven by the browser (the UI calls
 * {@code POST /bff/check-session} when its tab becomes visible) rather than a rolling
 * cookie, and the complement of the back-channel logout, which needs the provider to
 * reach this server.
 */
@ApplicationScoped
public class UserSessionCheck {

    /** What a check found. */
    public record Result(boolean active, UserSession session, Instant idTokenExpiresAt, Instant accessTokenExpiresAt) {
        static Result ended() {
            return new Result(false, null, null, null);
        }
    }

    private static final Logger LOG = Logger.getLogger(UserSessionCheck.class);

    private final ObjectMapper json = new ObjectMapper();

    @Inject
    IdpDiscovery discovery;
    @Inject
    UserSessionTokenStateManager sessions;
    @Inject
    UiTenant tenant;

    /**
     * Refreshes the session's tokens at its provider; {@link Result#active()} false when
     * the provider's session is gone (the row is deleted then).
     *
     * @throws IdpDiscovery.Unavailable when the provider cannot be asked
     */
    public Result check(String sessionId) {
        UserSessionStore store = sessions.store();
        Optional<UserSession> found = store.find(sessionId);
        if (found.isEmpty()) {
            return Result.ended();
        }
        UserSession session = found.get();
        if (session.refreshToken() == null) {
            LOG.debugf("Session %s has no refresh token to check with", session);
            return new Result(true, session, expiryOf(session.idToken()), null);
        }
        UiTenant.Idp idp = tenant.idp(session.idp())
            .orElseThrow(
                    () -> new IdpDiscovery.Unavailable("identity provider " + session.idp() + " is not configured"));
        IdpDiscovery.Metadata metadata = discovery.of(session.issuer());
        String form = "grant_type=refresh_token&client_id=" + encode(idp.clientId()) + "&refresh_token="
                + encode(session.refreshToken())
                + idp.clientSecret().filter(v -> !v.isBlank()).map(s -> "&client_secret=" + encode(s)).orElse("");
        HttpResponse<String> r;
        try {
            r = discovery.http()
                .send(HttpRequest.newBuilder(URI.create(metadata.tokenEndpoint()))
                    .timeout(IdpDiscovery.TIMEOUT)
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .POST(HttpRequest.BodyPublishers.ofString(form))
                    .build(), HttpResponse.BodyHandlers.ofString());
        }
        catch (IOException e) {
            throw new IdpDiscovery.Unavailable("token endpoint of " + session.issuer() + " failed: " + e.getMessage());
        }
        catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IdpDiscovery.Unavailable("token endpoint of " + session.issuer() + " interrupted");
        }
        if (r.statusCode() == 400 || r.statusCode() == 401) {
            String error = errorOf(r.body());
            LOG.infof("Session check: %s ended at %s (%s), row deleted", session, session.issuer(), error);
            store.delete(sessionId);
            return Result.ended();
        }
        if (r.statusCode() != 200) {
            throw new IdpDiscovery.Unavailable(
                    "token endpoint of " + session.issuer() + " answered HTTP " + r.statusCode());
        }
        JsonNode tokens;
        try {
            tokens = json.readTree(r.body());
        }
        catch (IOException e) {
            throw new IdpDiscovery.Unavailable("token endpoint of " + session.issuer() + " answered no JSON");
        }
        String idToken = tokens.path("id_token").asText(session.idToken());
        String accessToken = tokens.path("access_token").asText(session.accessToken());
        String refreshToken = tokens.path("refresh_token").asText(session.refreshToken());
        Long expiresIn = tokens.hasNonNull("expires_in") ? tokens.get("expires_in").asLong()
                : session.accessTokenExpiresIn();
        long now = System.currentTimeMillis();
        UserSession renewed = new UserSession(session.id(), session.idp(), session.issuer(), session.subject(),
                session.sid(), idToken, accessToken, refreshToken, expiresIn,
                tokens.path("scope").asText(session.scope()), session.createdAt(),
                sessions.expiresAt(idToken, refreshToken, now));
        store.save(renewed);
        LOG.debugf("Session check: %s renewed", renewed);
        return new Result(true, renewed, expiryOf(idToken),
                expiresIn == null ? null : Instant.ofEpochMilli(now + expiresIn * 1000));
    }

    private Instant expiryOf(String jwt) {
        long exp = sessions.expOf(jwt);
        return exp > 0 ? Instant.ofEpochSecond(exp) : null;
    }

    private String errorOf(String body) {
        try {
            JsonNode node = json.readTree(body);
            return node.path("error").asText("?") + ": " + node.path("error_description").asText("");
        }
        catch (IOException | RuntimeException e) {
            return body == null ? "?" : body.substring(0, Math.min(120, body.length()));
        }
    }

    private static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
