package com.github.thomasdarimont.keycloak.mcp.backend.keycloak;

import java.net.URI;
import java.time.Duration;
import java.util.Locale;
import java.util.Set;
import jakarta.ws.rs.client.ClientRequestContext;
import jakarta.ws.rs.client.ClientRequestFilter;
import jakarta.ws.rs.client.ClientResponseContext;
import jakarta.ws.rs.client.ClientResponseFilter;
import jakarta.ws.rs.core.Form;

import com.github.thomasdarimont.keycloak.mcp.backend.metrics.KcMcpMetrics;

/**
 * Measures every request the server makes to a Keycloak system: registered on each
 * RESTEasy client the admin client, the {@code private_key_jwt} token manager and the
 * token exchange use, since Quarkus does not instrument clients built outside CDI. Token
 * endpoint requests become {@code kc_mcp.keycloak.token.duration} (by grant), everything
 * else {@code kc_mcp.keycloak.request.duration} (by method and resource kind: users,
 * groups, clients, ... never an id). A request that gets no response at all (connection
 * refused, timeout) is not measured here; the tool call metrics show it as
 * {@code keycloak_unreachable}.
 */
public class KeycloakClientMetricsFilter implements ClientRequestFilter, ClientResponseFilter {

    private static final String START = KeycloakClientMetricsFilter.class.getName() + ".start";

    /** Resource kinds of the Admin REST API; anything else is {@code other}. */
    static final Set<String> RESOURCES = Set.of("users", "groups", "clients", "client-scopes", "roles", "roles-by-id",
            "identity-provider", "organizations", "components", "authentication", "events", "admin-events",
            "attack-detection", "sessions", "client-policies", "keys", "partial-export", "partialImport",
            "default-groups", "default-default-client-scopes", "default-optional-client-scopes", "localization",
            "workflows", "ui-ext");

    private final String system;
    private final KcMcpMetrics metrics;

    public KeycloakClientMetricsFilter(String system, KcMcpMetrics metrics) {
        this.system = system;
        this.metrics = metrics;
    }

    @Override
    public void filter(ClientRequestContext request) {
        request.setProperty(START, System.nanoTime());
    }

    @Override
    public void filter(ClientRequestContext request, ClientResponseContext response) {
        Object start = request.getProperty(START);
        if (!(start instanceof Long started)) {
            return;
        }
        Duration took = Duration.ofNanos(System.nanoTime() - started);
        int status = response.getStatus();
        String path = request.getUri() == null ? "" : request.getUri().getPath();
        if (path.endsWith("/protocol/openid-connect/token")) {
            metrics.keycloakToken(system, grant(request.getEntity()), status, took);
        }
        else {
            metrics.keycloakRequest(system, request.getMethod(), resource(request.getUri()), status, took);
        }
    }

    /**
     * The grant of a token request: {@code client_credentials}, {@code password},
     * {@code token-exchange}, ...
     */
    public static String grant(Object entity) {
        if (entity instanceof Form form) {
            String g = form.asMap().getFirst("grant_type");
            if (g != null) {
                // urn:ietf:params:oauth:grant-type:token-exchange -> token-exchange
                int colon = g.lastIndexOf(':');
                return colon >= 0 ? g.substring(colon + 1) : g;
            }
        }
        return "-";
    }

    /**
     * The kind of resource a request touches, without ids:
     * {@code /admin/realms/demo/users/42} is {@code users}, {@code /admin/realms/demo}
     * {@code realm}, {@code /admin/realms} {@code realms}, {@code /admin/serverinfo}
     * {@code serverinfo}.
     */
    public static String resource(URI uri) {
        if (uri == null || uri.getPath() == null) {
            return "other";
        }
        String[] p = uri.getPath().replaceAll("^/+|/+$", "").split("/");
        int admin = -1;
        for (int i = 0; i < p.length; i++) {
            if (p[i].equals("admin")) {
                admin = i;
                break;
            }
        }
        if (admin < 0 || admin + 1 >= p.length) {
            return "other";
        }
        String first = p[admin + 1].toLowerCase(Locale.ROOT);
        if (!first.equals("realms")) {
            return first.equals("serverinfo") ? "serverinfo" : "other";
        }
        if (admin + 2 >= p.length) {
            return "realms";
        }
        if (admin + 3 >= p.length) {
            return "realm";
        }
        String kind = p[admin + 3];
        return RESOURCES.contains(kind) ? kind : "other";
    }
}
