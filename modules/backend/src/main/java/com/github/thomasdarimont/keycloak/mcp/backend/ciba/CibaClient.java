package com.github.thomasdarimont.keycloak.mcp.backend.ciba;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

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

    static final Duration TIMEOUT = Duration.ofSeconds(10);

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

    private final HttpClient http;
    private final String issuer;
    private final String clientId;
    private final String clientSecret;
    private final CibaSettings.ClientAuth clientAuth;
    private final String scope;
    private final String acrValues;
    private final Map<String, Endpoints> endpoints = new ConcurrentHashMap<>();

    public CibaClient(HttpClient http, String issuer, String clientId, String clientSecret, String scope) {
        this(http, issuer, clientId, clientSecret, CibaSettings.ClientAuth.BASIC, scope, null);
    }

    public CibaClient(HttpClient http, String issuer, String clientId, String clientSecret,
            CibaSettings.ClientAuth clientAuth, String scope, String acrValues) {
        this.http = http == null ? newHttpClient() : http;
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
     * {@code send} parks the calling (virtual) thread while the request is in flight; the
     * client's own callbacks run on virtual threads too instead of its default platform
     * thread pool.
     */
    public static HttpClient newHttpClient() {
        return HttpClient.newBuilder()
            .connectTimeout(TIMEOUT)
            .executor(java.util.concurrent.Executors.newVirtualThreadPerTaskExecutor())
            .build();
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
        HttpResponse<String> r = send(endpoints().backchannel(), form.toString());
        JsonObject body = json(r);
        if (r.statusCode() != 200) {
            throw new CibaException("CIBA authentication request refused by " + issuer + ": HTTP " + r.statusCode()
                    + " " + body.getString("error", "") + " " + body.getString("error_description", ""));
        }
        String id = body.getString("auth_req_id");
        if (id == null) {
            throw new CibaException("CIBA authentication request: no auth_req_id in the response of " + issuer);
        }
        return new Started(id, body.getInteger("expires_in", 120), body.getInteger("interval", 5));
    }

    /** Asks the token endpoint whether the request was approved. */
    public Poll poll(String authReqId) {
        HttpResponse<String> r = send(endpoints().token(),
                "grant_type=" + enc(GRANT_TYPE) + "&auth_req_id=" + enc(authReqId));
        if (r.statusCode() == 200) {
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
                    "CIBA token request failed at " + issuer + ": HTTP " + r.statusCode() + " " + error + " " + detail);
        };
    }

    private Endpoints endpoints() {
        return endpoints.computeIfAbsent(issuer, i -> {
            HttpResponse<String> r;
            try {
                r = http.send(HttpRequest.newBuilder(URI.create(i + "/.well-known/openid-configuration"))
                    .timeout(TIMEOUT)
                    .GET()
                    .build(), HttpResponse.BodyHandlers.ofString());
            }
            catch (IOException e) {
                throw new CibaException("OpenID discovery of " + i + " failed: " + e.getMessage(), e);
            }
            catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new CibaException("OpenID discovery of " + i + " interrupted", e);
            }
            if (r.statusCode() != 200) {
                throw new CibaException("OpenID discovery of " + i + " answered HTTP " + r.statusCode());
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

    private HttpResponse<String> send(String url, String form) {
        HttpRequest.Builder request = HttpRequest.newBuilder(URI.create(url))
            .timeout(TIMEOUT)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header("Accept", "application/json");
        String body = form;
        if (clientAuth == CibaSettings.ClientAuth.POST) {
            body = form + "&client_id=" + enc(clientId) + "&client_secret=" + enc(clientSecret);
        }
        else {
            // RFC 6749 §2.3.1: the credentials are form-encoded before the Basic encoding
            request.header("Authorization", "Basic " + Base64.getEncoder()
                .encodeToString((enc(clientId) + ":" + enc(clientSecret)).getBytes(StandardCharsets.UTF_8)));
        }
        try {
            return http.send(request.POST(HttpRequest.BodyPublishers.ofString(body)).build(),
                    HttpResponse.BodyHandlers.ofString());
        }
        catch (IOException e) {
            throw new CibaException("CIBA request to " + url + " failed: " + e.getMessage(), e);
        }
        catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new CibaException("CIBA request to " + url + " interrupted", e);
        }
    }

    private static JsonObject json(HttpResponse<String> r) {
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
