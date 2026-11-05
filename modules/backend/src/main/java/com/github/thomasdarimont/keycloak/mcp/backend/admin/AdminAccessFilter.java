package com.github.thomasdarimont.keycloak.mcp.backend.admin;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Map;
import java.util.Optional;
import jakarta.inject.Inject;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;

import org.jboss.logging.Logger;
import org.jboss.resteasy.reactive.server.ServerRequestFilter;

import com.github.thomasdarimont.keycloak.mcp.access.Caller;
import com.github.thomasdarimont.keycloak.mcp.backend.guard.SecurityIdentityCallerProvider;
import com.github.thomasdarimont.keycloak.mcp.config.McpServerConfig;

import io.quarkus.security.identity.SecurityIdentity;

/**
 * Who may call the admin API: a request carrying the static {@code kc-mcp.admin.token},
 * or an access token of the trusted {@code kc-mcp.admin.issuer} with
 * {@code kc-mcp.admin.role} (verified by Quarkus OIDC, which {@code EntryTenantResolver}
 * points at that issuer for {@code /admin} requests). Anything else is 401 with a Bearer
 * challenge, a verified token without the role 403; with the API off every request is
 * 404.
 */
public class AdminAccessFilter {

    private static final Logger LOG = Logger.getLogger(AdminAccessFilter.class);

    @Inject
    McpServerConfig config;
    @Inject
    SecurityIdentity identity;

    @ServerRequestFilter
    public Optional<Response> filter(ContainerRequestContext ctx, UriInfo uri) {
        String path = "/" + uri.getPath().replaceFirst("^/+", "");
        if (!path.equals(AdminResource.PATH) && !path.startsWith(AdminResource.PATH + "/")) {
            return Optional.empty();
        }
        if (!config.admin().enabled()) {
            return Optional.of(error(404, "admin_api_disabled", "The admin API is off (kc-mcp.admin.enabled)."));
        }
        if (staticTokenMatches(ctx.getHeaderString("Authorization"), config.admin().token().orElse(null))) {
            return Optional.empty();
        }
        if (identity == null || identity.isAnonymous()) {
            return Optional.of(Response
                .fromResponse(error(401, "unauthorized",
                        "The admin API needs the bearer token" + " of kc-mcp.admin.token or an access token of "
                                + config.admin().issuer().orElse("the trusted issuer") + " with the role "
                                + config.admin().role() + "."))
                .header("WWW-Authenticate", "Bearer realm=\"keycloak-mcp-server admin\"")
                .build());
        }
        Caller caller = SecurityIdentityCallerProvider.fromIdentity(identity);
        if (!caller.hasRole(config.admin().role())) {
            LOG.infof("Admin API: %s refused, lacks the role %s", caller, config.admin().role());
            return Optional.of(error(403, "forbidden",
                    "The admin API needs the role " + config.admin().role() + ", which the caller lacks."));
        }
        LOG.debugf("Admin API: %s", caller);
        return Optional.empty();
    }

    /**
     * Constant-time comparison of a {@code Bearer} header with the configured static
     * token.
     */
    public static boolean staticTokenMatches(String authorization, String token) {
        if (authorization == null || token == null || token.isBlank()
                || !authorization.regionMatches(true, 0, "Bearer ", 0, 7)) {
            return false;
        }
        return MessageDigest.isEqual(authorization.substring(7).trim().getBytes(StandardCharsets.UTF_8),
                token.getBytes(StandardCharsets.UTF_8));
    }

    private static Response error(int status, String code, String message) {
        return Response.status(status)
            .type(MediaType.APPLICATION_JSON)
            .entity(Map.of("error", code, "message", message))
            .build();
    }
}
