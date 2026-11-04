package com.github.thomasdarimont.keycloak.mcp.server.guard;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.vertx.http.runtime.security.HttpSecurityPolicy;
import io.smallrye.mutiny.Uni;
import io.vertx.ext.web.RoutingContext;

/**
 * HTTP policy bound to the MCP paths
 * ({@code quarkus.http.auth.permission.mcp.policy=kc-mcp-caller}): denies anonymous
 * requests when a caller is required, which makes Quarkus answer with the bearer
 * challenge ({@code WWW-Authenticate: Bearer resource_metadata="..."}) that OAuth-capable
 * MCP clients act on. Otherwise every request passes and the identity, if any, only feeds
 * the {@link com.github.thomasdarimont.keycloak.mcp.spi.Caller}.
 */
@ApplicationScoped
public class McpEndpointPolicy implements HttpSecurityPolicy {

    public static final String NAME = "kc-mcp-caller";

    @Inject
    CallerAuth callerAuth;

    @Override
    public String name() {
        return NAME;
    }

    @Override
    public Uni<CheckResult> checkPermission(RoutingContext request, Uni<SecurityIdentity> identity,
            AuthorizationRequestContext requestContext) {
        if (!callerAuth.required()) {
            return CheckResult.permit();
        }
        return identity.map(i -> i == null || i.isAnonymous() ? CheckResult.DENY : CheckResult.PERMIT);
    }
}
