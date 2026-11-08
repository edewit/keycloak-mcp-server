package com.github.thomasdarimont.keycloak.mcp.backend.keycloak;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import org.jboss.logging.Logger;

import com.github.thomasdarimont.keycloak.mcp.access.CallerIssuerPolicy;
import com.github.thomasdarimont.keycloak.mcp.access.CallerIssuerPolicy.Decision;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystem;
import com.github.thomasdarimont.keycloak.mcp.spi.Extension;

/**
 * The chain of {@link CallerIssuerPolicy}s a system's admin client asks before it uses a
 * caller's token: the registered policies in order, then the built-in rule, which allows
 * the system's own Keycloak and the system's {@code trustedIssuers} (configured, from the
 * systems file or registered) and denies the rest. The system record is the only source:
 * configured defaults were applied when it was resolved.
 */
public final class CallerIssuerPolicies {

    private static final Logger LOG = Logger.getLogger(CallerIssuerPolicies.class);

    private final List<CallerIssuerPolicy> custom;

    public CallerIssuerPolicies(List<CallerIssuerPolicy> custom) {
        List<CallerIssuerPolicy> ordered = new ArrayList<>(custom);
        ordered.sort(Comparator.comparingInt(Extension::order));
        this.custom = List.copyOf(ordered);
    }

    /** No registered policies: the built-in rule alone. */
    public static CallerIssuerPolicies builtIn() {
        return new CallerIssuerPolicies(List.of());
    }

    /**
     * Why a token of {@code issuer} may not be used at {@code system}, empty when it may.
     *
     * @param ownBases the issuer bases of the system's own Keycloak
     * ({@link DefaultKeycloakAdmin#callerIssuerBases})
     */
    public Optional<String> refusal(String issuer, KeycloakSystem system, Set<String> ownBases) {
        for (CallerIssuerPolicy policy : custom) {
            Decision d;
            try {
                d = policy.decide(issuer, system);
            }
            catch (RuntimeException e) {
                LOG.warnf("CallerIssuerPolicy '%s' failed for system '%s': %s; treated as a denial", policy.id(),
                        system.name(), e.toString());
                d = Decision.DENY;
            }
            if (d == Decision.ALLOW) {
                return Optional.empty();
            }
            if (d == Decision.DENY) {
                return Optional.of("The caller's token was issued by " + issuer + ", which policy '" + policy.id()
                        + "' does not accept for system '" + system.name() + "'.");
            }
        }
        Set<String> accepted = new HashSet<>(ownBases);
        for (String trusted : system.trustedIssuers()) {
            accepted.add(DefaultKeycloakAdmin.base(trusted));
        }
        if (accepted.contains(DefaultKeycloakAdmin.base(issuer))) {
            return Optional.empty();
        }
        return Optional.of("The caller's token was issued by " + issuer + "; system '" + system.name()
                + "' acts only for callers of " + system.publicUrl() + " (and its trusted issuers). Log in at that"
                + " system's entry (/mcp/systems/" + system.name() + ") instead.");
    }
}
