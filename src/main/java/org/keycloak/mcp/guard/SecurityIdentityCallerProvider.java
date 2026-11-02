package org.keycloak.mcp.guard;

import java.security.Principal;
import java.util.LinkedHashSet;
import java.util.Set;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;

import org.eclipse.microprofile.jwt.JsonWebToken;
import org.jboss.logging.Logger;
import org.keycloak.mcp.spi.Caller;
import org.keycloak.mcp.spi.CallerProvider;

import io.quarkiverse.mcp.server.FeatureManager.FeatureArguments;
import io.quarkus.arc.Arc;
import io.quarkus.arc.DefaultBean;
import io.quarkus.security.identity.CurrentIdentityAssociation;
import io.quarkus.security.identity.SecurityIdentity;

/**
 * Maps the request's {@link SecurityIdentity} to a {@link Caller}. With a JWT principal (OIDC) the subject, the
 * preferred username, the issuing realm and the realm / client roles are taken from the token.
 */
@ApplicationScoped
@DefaultBean
public class SecurityIdentityCallerProvider implements CallerProvider {

    private static final Logger LOG = Logger.getLogger(SecurityIdentityCallerProvider.class);

    @Inject
    Instance<CurrentIdentityAssociation> identities;

    @Override
    public Caller current(FeatureArguments args) {
        try {
            if (!identities.isResolvable() || !Arc.container().requestContext().isActive()) {
                return Caller.NONE;
            }
            return fromIdentity(identities.get().getIdentity());
        } catch (RuntimeException e) {
            LOG.debugf("No caller identity available: %s", e.toString());
            return Caller.NONE;
        }
    }

    public static Caller fromIdentity(SecurityIdentity identity) {
        if (identity == null || identity.isAnonymous()) {
            return Caller.NONE;
        }
        Principal principal = identity.getPrincipal();
        Set<String> roles = new LinkedHashSet<>();
        for (String r : identity.getRoles()) {
            roles.add(r.contains(".") || r.startsWith("realm:") ? r : "realm:" + r);
        }
        if (principal instanceof JsonWebToken jwt) {
            String name = jwt.getClaim("preferred_username");
            if (name == null) {
                name = jwt.getName();
            }
            Object realmAccess = jwt.getClaim("realm_access");
            addRoles(roles, realmAccess, "realm:");
            Object resourceAccess = jwt.getClaim("resource_access");
            if (resourceAccess instanceof jakarta.json.JsonObject ra) {
                for (String client : ra.keySet()) {
                    addRoles(roles, ra.get(client), client + ".");
                }
            }
            return Caller.of(jwt.getSubject(), name, realmOf(jwt.getIssuer()), roles);
        }
        return Caller.of(principal.getName(), principal.getName(), null, roles);
    }

    private static void addRoles(Set<String> roles, Object access, String prefix) {
        if (access instanceof jakarta.json.JsonObject o && o.containsKey("roles")) {
            for (jakarta.json.JsonValue v : o.getJsonArray("roles")) {
                if (v instanceof jakarta.json.JsonString s) {
                    roles.add(prefix + s.getString());
                }
            }
        }
    }

    /** {@code https://host/realms/demo} -> {@code demo}. */
    static String realmOf(String issuer) {
        if (issuer == null) {
            return null;
        }
        int i = issuer.indexOf("/realms/");
        if (i < 0) {
            return null;
        }
        String rest = issuer.substring(i + "/realms/".length());
        int slash = rest.indexOf('/');
        return slash < 0 ? rest : rest.substring(0, slash);
    }
}
