package com.github.thomasdarimont.keycloak.mcp.backend.authzen;

import java.net.URI;
import java.util.UUID;
import jakarta.ws.rs.ProcessingException;
import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.client.Invocation;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import com.github.thomasdarimont.keycloak.mcp.backend.oauth.ClientCredentialsTokens;

import io.vertx.core.json.DecodeException;
import io.vertx.core.json.JsonObject;

/**
 * Talks to one PDP's evaluation endpoint. With {@code auth=client-credentials} the bearer
 * token comes from {@link ClientCredentialsTokens}; a 401 renews it once.
 */
class AuthZenClient {

    /** What the PDP said: its decision and the response context (reasons, our hints). */
    record Answer(boolean decision, JsonObject context, String requestId) {
    }

    /** The PDP could not be asked or answered something that is not a decision. */
    static class PdpException extends RuntimeException {
        PdpException(String message) {
            super(message);
        }

        PdpException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    private final Client http;
    private final AuthZenSettings settings;
    private final ClientCredentialsTokens tokens;

    /**
     * @param tokens the token source with {@code auth=client-credentials}, else
     * {@code null}
     */
    AuthZenClient(Client http, AuthZenSettings settings, ClientCredentialsTokens tokens) {
        this.http = http;
        this.settings = settings;
        this.tokens = tokens;
    }

    Answer evaluate(JsonObject request, String system, String realm) {
        String requestId = UUID.randomUUID().toString();
        URI endpoint = settings.endpoint(system, realm);
        try {
            String token = tokens == null ? null : tokens.accessToken();
            try (Response r = send(endpoint, request, requestId, token)) {
                if (r.getStatus() != 401 || tokens == null) {
                    return answer(r, requestId);
                }
            }
            try (Response retry = send(endpoint, request, requestId, tokens.renew(token))) {
                return answer(retry, requestId);
            }
        }
        catch (ProcessingException e) {
            throw new PdpException("the PDP at " + endpoint + " could not be reached: " + e.getMessage(), e);
        }
        catch (ClientCredentialsTokens.TokenException e) {
            throw new PdpException("no token for the PDP: " + e.getMessage(), e);
        }
    }

    private Response send(URI endpoint, JsonObject request, String requestId, String token) {
        Invocation.Builder b = http.target(endpoint)
            .request(MediaType.APPLICATION_JSON_TYPE)
            .header("X-Request-ID", requestId);
        if (settings.auth() == AuthZenSettings.Auth.HEADER) {
            b.header(settings.headerName(), settings.headerValue());
        }
        else if (token != null) {
            b.header(HttpHeaders.AUTHORIZATION, "Bearer " + token);
        }
        return b.post(Entity.entity(request.encode(), MediaType.APPLICATION_JSON_TYPE));
    }

    private static Answer answer(Response r, String requestId) {
        String body = r.hasEntity() ? r.readEntity(String.class) : "";
        if (r.getStatus() != 200) {
            throw new PdpException("the PDP answered HTTP " + r.getStatus() + " (request " + requestId + ")");
        }
        JsonObject json;
        try {
            json = new JsonObject(body);
        }
        catch (DecodeException e) {
            throw new PdpException("the PDP's answer is not JSON (request " + requestId + ")", e);
        }
        if (!(json.getValue("decision") instanceof Boolean decision)) {
            throw new PdpException("the PDP's answer has no boolean decision (request " + requestId + ")");
        }
        JsonObject context = json.getValue("context") instanceof JsonObject c ? c : new JsonObject();
        return new Answer(decision, context, requestId);
    }
}
