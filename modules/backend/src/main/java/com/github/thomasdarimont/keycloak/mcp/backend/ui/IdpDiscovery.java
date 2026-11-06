package com.github.thomasdarimont.keycloak.mcp.backend.ui;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import jakarta.enterprise.context.ApplicationScoped;

import org.jboss.logging.Logger;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * The OpenID Connect discovery documents of the UI's identity providers, fetched once per
 * issuer: where their keys ({@code jwks_uri}) and their token endpoint are. Quarkus keeps
 * its own copy for the login; this one serves the parts the server calls itself
 * (back-channel logout tokens, session checks).
 */
@ApplicationScoped
public class IdpDiscovery {

    /** What the server needs of a provider. */
    public record Metadata(String issuer, String jwksUri, String tokenEndpoint) {
    }

    /** A provider that did not answer or answered nonsense. */
    public static class Unavailable extends RuntimeException {
        public Unavailable(String message) {
            super(message);
        }
    }

    private static final Logger LOG = Logger.getLogger(IdpDiscovery.class);
    static final Duration TIMEOUT = Duration.ofSeconds(10);

    private final ObjectMapper json = new ObjectMapper();
    private final HttpClient http = HttpClient.newBuilder().connectTimeout(TIMEOUT).build();
    private final Map<String, Metadata> byIssuer = new ConcurrentHashMap<>();

    public Metadata of(String issuer) {
        return byIssuer.computeIfAbsent(issuer, this::fetch);
    }

    /** The HTTP client the server talks to providers with. */
    HttpClient http() {
        return http;
    }

    private Metadata fetch(String issuer) {
        URI discovery = URI.create(issuer.endsWith("/") ? issuer + ".well-known/openid-configuration"
                : issuer + "/.well-known/openid-configuration");
        try {
            HttpResponse<String> r = http.send(HttpRequest.newBuilder(discovery).timeout(TIMEOUT).GET().build(),
                    HttpResponse.BodyHandlers.ofString());
            if (r.statusCode() != 200) {
                throw new Unavailable("discovery of " + issuer + " answered HTTP " + r.statusCode());
            }
            JsonNode doc = json.readTree(r.body());
            String jwks = doc.path("jwks_uri").asText(null);
            String token = doc.path("token_endpoint").asText(null);
            if (jwks == null || token == null) {
                throw new Unavailable("discovery of " + issuer + " names no jwks_uri or token_endpoint");
            }
            LOG.debugf("Identity provider %s: keys at %s, tokens at %s", issuer, jwks, token);
            return new Metadata(issuer, jwks, token);
        }
        catch (IOException e) {
            throw new Unavailable("discovery of " + issuer + " failed: " + e.getMessage());
        }
        catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new Unavailable("discovery of " + issuer + " interrupted");
        }
    }
}
