package com.github.thomasdarimont.keycloak.mcp.backend.ciba;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import jakarta.ws.rs.ProcessingException;
import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.client.Invocation;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import com.github.thomasdarimont.keycloak.mcp.backend.http.OutboundClients;

import io.vertx.core.json.JsonObject;

/**
 * OpenID Connect Client Initiated Backchannel Authentication (CIBA), poll mode, against
 * one OpenID provider: {@link #start} files the authentication request for a user,
 * {@link #poll} asks the token endpoint whether the user has approved it on their device.
 * Standard requests and error codes only ({@code authorization_pending},
 * {@code slow_down}, {@code access_denied}, {@code expired_token}; {@code invalid_grant}
 * is taken as expired, as some providers answer); the tokens issued on approval are not
 * used for anything, the approval is.
 */
public class CibaClient {

    /** CIBA grant type at the token endpoint. */
    public static final String GRANT_TYPE = "urn:openid:params:grant-type:ciba";

    /** What the token endpoint said. */
    public enum Status {
        APPROVED, PENDING, SLOW_DOWN, DENIED, EXPIRED
    }

    public record Started(String authReqId, int expiresIn, int interval) {
    }

    /**
     * @param idToken the ID token of the approval ({@link Status#APPROVED}), to verify
     * who approved
     */
    public record Poll(Status status, String detail, String idToken) {
        public Poll(Status status, String detail) {
            this(status, detail, null);
        }
    }

    /** A CIBA request that could not be made or that the provider refused. */
    public static class CibaException extends RuntimeException {
        public CibaException(String message) {
            super(message);
        }

        public CibaException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    private record Endpoints(String backchannel, String token, String jwks) {
    }

    /** Status and body of an answer. */
    private record Answer(int status, String body) {
    }

    private final Client http;
    private final String issuer;
    private final String clientId;
    private final String clientSecret;
    private final CibaSettings.ClientAuth clientAuth;
    private final String scope;
    private final String acrValues;
    private final Map<String, Endpoints> endpoints = new ConcurrentHashMap<>();

    public CibaClient(Client http, String issuer, String clientId, String clientSecret, String scope) {
        this(http, issuer, clientId, clientSecret, CibaSettings.ClientAuth.BASIC, scope, null);
    }

    /**
     * @param http the JAX-RS client to use (shared, closed by its owner); {@code null}
     * makes one with the default trust
     */
    public CibaClient(Client http, String issuer, String clientId, String clientSecret,
            CibaSettings.ClientAuth clientAuth, String scope, String acrValues) {
        this.http = http == null ? OutboundClients.create() : http;
        this.issuer = issuer.endsWith("/") ? issuer.substring(0, issuer.length() - 1) : issuer;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.clientAuth = clientAuth == null ? CibaSettings.ClientAuth.BASIC : clientAuth;
        this.scope = scope;
        this.acrValues = acrValues;
    }

    public String issuer() {
        return issuer;
    }

    /** The provider's {@code jwks_uri}, for verifying the ID token of an approval. */
    public String jwksUri() {
        return endpoints().jwks();
    }

    /**
     * Files the authentication request; the user sees the binding message on their
     * device.
     *
     * @param bindingMessage {@code null} sends none
     * @param requestedExpiry seconds to ask for, {@code 0} leaves it to the provider
     * @param extra additional request parameters for the device (providers forward or
     * ignore them; Keycloak passes up to five as {@code additional_parameters})
     */
    public Started start(String loginHint, String bindingMessage, int requestedExpiry, Map<String, String> extra) {
        StringBuilder form = new StringBuilder("scope=").append(enc(scope))
            .append("&login_hint=")
            .append(enc(loginHint));
        for (Map.Entry<String, String> e : (extra == null ? Map.<String, String>of() : extra).entrySet()) {
            if (e.getValue() != null && !e.getValue().isBlank()) {
                form.append('&').append(enc(e.getKey())).append('=').append(enc(e.getValue()));
            }
        }
        if (bindingMessage != null) {
            form.append("&binding_message=").append(enc(bindingMessage));
        }
        if (acrValues != null) {
            form.append("&acr_values=").append(enc(acrValues));
        }
        if (requestedExpiry > 0) {
            form.append("&requested_expiry=").append(requestedExpiry);
        }
        Answer r = send(endpoints().backchannel(), form.toString());
        JsonObject body = json(r);
        if (r.status() != 200) {
            throw new CibaException("CIBA authentication request refused by " + issuer + ": HTTP " + r.status() + " "
                    + body.getString("error", "") + " " + body.getString("error_description", ""));
        }
        String id = body.getString("auth_req_id");
        if (id == null) {
            throw new CibaException("CIBA authentication request: no auth_req_id in the response of " + issuer);
        }
        return new Started(id, body.getInteger("expires_in", 120), body.getInteger("interval", 5));
    }

    /** Asks the token endpoint whether the request was approved. */
    public Poll poll(String authReqId) {
        Answer r = send(endpoints().token(), "grant_type=" + enc(GRANT_TYPE) + "&auth_req_id=" + enc(authReqId));
        if (r.status() == 200) {
            return new Poll(Status.APPROVED, null, json(r).getString("id_token"));
        }
        JsonObject body = json(r);
        String error = body.getString("error", "");
        String detail = body.getString("error_description", error);
        return switch (error) {
            case "authorization_pending" -> new Poll(Status.PENDING, detail);
            case "slow_down" -> new Poll(Status.SLOW_DOWN, detail);
            case "access_denied" -> new Poll(Status.DENIED, detail);
            case "expired_token", "invalid_grant" -> new Poll(Status.EXPIRED, detail);
            default -> throw new CibaException(
                    "CIBA token request failed at " + issuer + ": HTTP " + r.status() + " " + error + " " + detail);
        };
    }

    private Endpoints endpoints() {
        return endpoints.computeIfAbsent(issuer, i -> {
            Answer r;
            try (Response resp = http.target(i + "/.well-known/openid-configuration")
                .request(MediaType.APPLICATION_JSON_TYPE)
                .get()) {
                r = new Answer(resp.getStatus(), resp.hasEntity() ? resp.readEntity(String.class) : "");
            }
            catch (ProcessingException e) {
                throw new CibaException("OpenID discovery of " + i + " failed: " + rootMessage(e), e);
            }
            if (r.status() != 200) {
                throw new CibaException("OpenID discovery of " + i + " answered HTTP " + r.status());
            }
            JsonObject meta = new JsonObject(r.body());
            String bc = meta.getString("backchannel_authentication_endpoint");
            String token = meta.getString("token_endpoint");
            String jwks = meta.getString("jwks_uri");
            if (bc == null || token == null) {
                throw new CibaException(i + " does not advertise CIBA (backchannel_authentication_endpoint)");
            }
            if (jwks == null) {
                throw new CibaException(i + " does not advertise jwks_uri, so approvals cannot be verified");
            }
            return new Endpoints(bc, token, jwks);
        });
    }

    private Answer send(String url, String form) {
        Invocation.Builder request = http.target(url).request(MediaType.APPLICATION_JSON_TYPE);
        String body = form;
        if (clientAuth == CibaSettings.ClientAuth.POST) {
            body = form + "&client_id=" + enc(clientId) + "&client_secret=" + enc(clientSecret);
        }
        else {
            // RFC 6749 §2.3.1: the credentials are form-encoded before the Basic encoding
            request.header("Authorization", "Basic " + Base64.getEncoder()
                .encodeToString((enc(clientId) + ":" + enc(clientSecret)).getBytes(StandardCharsets.UTF_8)));
        }
        try (Response r = request.post(Entity.entity(body, MediaType.APPLICATION_FORM_URLENCODED_TYPE))) {
            return new Answer(r.getStatus(), r.hasEntity() ? r.readEntity(String.class) : "");
        }
        catch (ProcessingException e) {
            throw new CibaException("CIBA request to " + url + " failed: " + rootMessage(e), e);
        }
    }

    private static String rootMessage(Throwable t) {
        Throwable c = t;
        while (c.getCause() != null && c.getCause() != c) {
            c = c.getCause();
        }
        return c.getMessage() == null ? c.getClass().getSimpleName() : c.getMessage();
    }

    private static JsonObject json(Answer r) {
        try {
            return r.body() == null || r.body().isBlank() ? new JsonObject() : new JsonObject(r.body());
        }
        catch (RuntimeException e) {
            return new JsonObject();
        }
    }

    private static String enc(String v) {
        return URLEncoder.encode(v == null ? "" : v, StandardCharsets.UTF_8);
    }
}
