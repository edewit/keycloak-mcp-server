package com.github.thomasdarimont.keycloak.mcp.backend.guard;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import com.github.thomasdarimont.keycloak.mcp.backend.http.HttpPaths;

import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.vertx.http.runtime.security.HttpSecurityPolicy;
import io.smallrye.mutiny.Uni;
import io.vertx.ext.web.RoutingContext;

/**
 * HTTP policy on every path
 * ({@code quarkus.http.auth.permission.mcp.policy=kc-mcp-caller}) that acts on the MCP
 * endpoint and its entries only, wherever {@code quarkus.http.root-path} and
 * {@code quarkus.mcp.server.http.root-path} put them ({@link HttpPaths}): denies
 * anonymous requests there when a caller is required, which makes Quarkus answer with the
 * bearer challenge ({@code WWW-Authenticate: Bearer resource_metadata="..."}) that
 * OAuth-capable MCP clients act on. Everything else passes and the identity, if any, only
 * feeds the {@link com.github.thomasdarimont.keycloak.mcp.access.Caller}. The path is
 * checked here rather than in the permission's {@code paths}, whose absolute patterns do
 * not follow the HTTP root path.
 */
@ApplicationScoped
public class McpEndpointPolicy implements HttpSecurityPolicy {

    public static final String NAME = "kc-mcp-caller";

    @Inject
    CallerAuth callerAuth;
    @Inject
    HttpPaths paths;

    @Override
    public String name() {
        return NAME;
    }

    @Override
    public Uni<CheckResult> checkPermission(RoutingContext request, Uni<SecurityIdentity> identity,
            AuthorizationRequestContext requestContext) {
        if (!callerAuth.required() || !paths.underMcp(request.normalizedPath())) {
            return CheckResult.permit();
        }
        return identity.map(i -> i == null || i.isAnonymous() ? CheckResult.DENY : CheckResult.PERMIT);
    }
}
