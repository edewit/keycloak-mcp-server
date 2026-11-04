package org.keycloak.mcp.server.spi;

import java.util.LinkedHashSet;
import java.util.Set;
import jakarta.annotation.Priority;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Alternative;
import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;

import org.keycloak.mcp.server.guard.SecurityIdentityCallerProvider;
import org.keycloak.mcp.spi.Caller;

import io.quarkiverse.mcp.server.FeatureManager.FeatureArguments;
import io.quarkus.arc.Arc;
import io.quarkus.security.identity.CurrentIdentityAssociation;
import io.vertx.core.json.JsonObject;

/**
 * Test-only caller source: the MCP client names the caller in {@code _meta} of the
 * tools/call request ({@code kc-mcp/test-caller}, optional
 * {@code kc-mcp/test-caller-realm}, {@code kc-mcp/test-caller-roles} csv). Without such a
 * hint it behaves like the default provider (request's {@code SecurityIdentity}), so the
 * OIDC integration test sees real callers.
 */
@Alternative
@Priority(1)
@ApplicationScoped
public class MetaCallerProvider implements CallerProvider {

    public static final String CALLER = "kc-mcp/test-caller";
    public static final String REALM = "kc-mcp/test-caller-realm";
    public static final String ROLES = "kc-mcp/test-caller-roles";

    @Inject
    Instance<CurrentIdentityAssociation> identities;

    @Override
    public Caller current(FeatureArguments args) {
        JsonObject meta = args.meta() == null ? new JsonObject() : args.meta().asJsonObject();
        String name = meta.getString(CALLER);
        if (name == null || name.isBlank()) {
            return identityAvailable() ? SecurityIdentityCallerProvider.fromIdentity(identities.get().getIdentity())
                    : Caller.NONE;
        }
        Set<String> roles = new LinkedHashSet<>();
        String csv = meta.getString(ROLES);
        if (csv != null) {
            for (String r : csv.split(",")) {
                if (!r.isBlank()) {
                    roles.add(r.trim());
                }
            }
        }
        return Caller.of(name, name, meta.getString(REALM), roles);
    }

    @Override
    public String accessToken(FeatureArguments args) {
        return identityAvailable() ? SecurityIdentityCallerProvider.tokenOf(identities.get().getIdentity()) : null;
    }

    private boolean identityAvailable() {
        try {
            return identities.isResolvable() && Arc.container().requestContext().isActive();
        }
        catch (RuntimeException e) {
            return false;
        }
    }
}
