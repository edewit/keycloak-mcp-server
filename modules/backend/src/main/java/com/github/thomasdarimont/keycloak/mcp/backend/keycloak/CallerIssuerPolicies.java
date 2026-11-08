package com.github.thomasdarimont.keycloak.mcp.backend.keycloak;

import java.util.ArrayList;
import java.util.Comparator;
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
 * the system's own Keycloak (every realm of it) and the system's {@code trustedIssuers}
 * (configured, from the systems file or registered) and denies the rest. A trusted issuer
 * naming a realm ({@code https://sso.example/realms/demo}) trusts exactly that realm's
 * tokens; one naming only the Keycloak ({@code https://sso.example}) trusts every realm
 * of it. The system record is the only source: configured defaults were applied when it
 * was resolved.
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
        if (ownBases.contains(DefaultKeycloakAdmin.base(issuer))) {
            return Optional.empty();
        }
        for (String trusted : system.trustedIssuers()) {
            if (trusts(trusted, issuer)) {
                return Optional.empty();
            }
        }
        return Optional.of("The caller's token was issued by " + issuer + "; system '" + system.name()
                + "' acts only for callers of " + system.publicUrl() + " (and its trusted issuers). Log in at that"
                + " system's entry (/mcp/systems/" + system.name() + ") instead.");
    }

    /**
     * Whether a trusted-issuer entry covers an issuer: an entry with a realm path is that
     * one issuer, an entry without is a whole Keycloak and covers every realm of it.
     */
    static boolean trusts(String trusted, String issuer) {
        String entry = noTrailingSlash(trusted);
        if (entry.contains("/realms/")) {
            return entry.equals(noTrailingSlash(issuer));
        }
        return entry.equals(DefaultKeycloakAdmin.base(issuer));
    }

    private static String noTrailingSlash(String v) {
        String t = v.trim();
        return t.endsWith("/") ? t.substring(0, t.length() - 1) : t;
    }
}
