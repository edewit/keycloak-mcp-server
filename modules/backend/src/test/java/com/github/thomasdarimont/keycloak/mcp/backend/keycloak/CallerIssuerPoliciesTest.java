package com.github.thomasdarimont.keycloak.mcp.backend.keycloak;

import java.util.List;
import java.util.Optional;
import java.util.Set;

import org.junit.jupiter.api.Test;

import com.github.thomasdarimont.keycloak.mcp.access.CallerIssuerPolicy;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystem;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CallerIssuerPoliciesTest {

    static final KeycloakSystem B = KeycloakSystem.builder("b", "https://sso-b.example").build();

    static final Set<String> OWN = DefaultKeycloakAdmin.callerIssuerBases(B, List.of());

    static CallerIssuerPolicy policy(String id, CallerIssuerPolicy.Decision decision, int order) {
        return new CallerIssuerPolicy() {
            @Override
            public String id() {
                return id;
            }

            @Override
            public int order() {
                return order;
            }

            @Override
            public Decision decide(String issuer, KeycloakSystem system) {
                return decision;
            }
        };
    }

    @Test
    void theBuiltInRuleAllowsTheOwnKeycloakOnly() {
        CallerIssuerPolicies p = CallerIssuerPolicies.builtIn();
        assertEquals(Optional.empty(), p.refusal("https://sso-b.example/realms/any", B, OWN));
        Optional<String> refusal = p.refusal("https://sso-a.example/realms/demo", B, OWN);
        assertTrue(refusal.orElseThrow().contains("sso-a.example/realms/demo"), refusal.toString());
        assertTrue(refusal.orElseThrow().contains("/mcp/systems/b"), refusal.toString());
    }

    @Test
    void aRegisteredPolicyDecidesFirstAndTheChainStopsAtItsDecision() {
        String foreign = "https://sso-a.example/realms/demo";
        CallerIssuerPolicies allow = new CallerIssuerPolicies(
                List.of(policy("deny-later", CallerIssuerPolicy.Decision.DENY, 10),
                        policy("federation", CallerIssuerPolicy.Decision.ALLOW, 0)));
        assertEquals(Optional.empty(), allow.refusal(foreign, B, OWN), "the lower order allows first");

        CallerIssuerPolicies deny = new CallerIssuerPolicies(
                List.of(policy("blocklist", CallerIssuerPolicy.Decision.DENY, 0)));
        Optional<String> refusal = deny.refusal("https://sso-b.example/realms/demo", B, OWN);
        assertTrue(refusal.orElseThrow().contains("'blocklist'"), "a policy may deny even the own Keycloak");

        CallerIssuerPolicies abstain = new CallerIssuerPolicies(
                List.of(policy("quiet", CallerIssuerPolicy.Decision.ABSTAIN, 0)));
        assertTrue(abstain.refusal(foreign, B, OWN).isPresent(), "abstaining leaves it to the built-in rule");
    }

    @Test
    void aSystemsTrustedIssuersAreAccepted() {
        KeycloakSystem trusting = KeycloakSystem.builder("b", "https://sso-b.example")
            .trustedIssuer("https://sso-a.example/realms/demo")
            .build();
        Set<String> own = DefaultKeycloakAdmin.callerIssuerBases(trusting, List.of());
        CallerIssuerPolicies policy = CallerIssuerPolicies.builtIn();
        assertEquals(Optional.empty(), policy.refusal("https://sso-a.example/realms/demo", trusting, own));
        assertEquals(Optional.empty(), policy.refusal("https://sso-a.example/realms/demo/", trusting, own));
        assertTrue(policy.refusal("https://sso-a.example/realms/other", trusting, own).isPresent(),
                "a realm entry is that realm alone");
        assertTrue(policy.refusal("https://sso-c.example/realms/x", trusting, own).isPresent());

        KeycloakSystem trustingAll = trusting.toBuilder().trustedIssuers(List.of("https://sso-a.example/")).build();
        assertEquals(Optional.empty(), policy.refusal("https://sso-a.example/realms/other", trustingAll, own),
                "a base entry is every realm of that Keycloak");
        assertTrue(policy.refusal("https://sso-a.example.evil/realms/demo", trustingAll, own).isPresent());

        // a trusted Keycloak under the legacy context path, as a realm and as a whole
        KeycloakSystem trustingLegacy = trusting.toBuilder()
            .trustedIssuers(List.of("https://host1/auth/realms/foo", "https://host2/auth"))
            .build();
        assertEquals(Optional.empty(), policy.refusal("https://host1/auth/realms/foo", trustingLegacy, own));
        assertTrue(policy.refusal("https://host1/auth/realms/bar", trustingLegacy, own).isPresent());
        assertEquals(Optional.empty(), policy.refusal("https://host2/auth/realms/bar", trustingLegacy, own));
        assertTrue(policy.refusal("https://host2/realms/bar", trustingLegacy, own).isPresent(),
                "host2 without /auth is not the trusted Keycloak");
    }

    @Test
    void keycloaksOnOneHostUnderDifferentContextPathsAreDifferentKeycloaks() {
        KeycloakSystem auth1 = KeycloakSystem.builder("one", "https://host1/auth1").build();
        Set<String> own1 = DefaultKeycloakAdmin.callerIssuerBases(auth1, List.of());
        CallerIssuerPolicies policy = CallerIssuerPolicies.builtIn();
        assertEquals(Optional.empty(), policy.refusal("https://host1/auth1/realms/foo", auth1, own1));
        assertTrue(policy.refusal("https://host1/auth2/realms/bar", auth1, own1).isPresent(),
                "the neighbour under /auth2 is another Keycloak");

        KeycloakSystem trustingHost = auth1.toBuilder().trustedIssuers(List.of("https://host1")).build();
        assertTrue(policy.refusal("https://host1/auth2/realms/bar", trustingHost, own1).isPresent(),
                "an entry is matched whole, never as a prefix: the host alone trusts no instance under it");
        KeycloakSystem trustingAuth2 = auth1.toBuilder().trustedIssuers(List.of("https://host1/auth2")).build();
        assertEquals(Optional.empty(), policy.refusal("https://host1/auth2/realms/bar", trustingAuth2, own1));
    }

    @Test
    void aFailingPolicyCountsAsADenial() {
        CallerIssuerPolicy broken = new CallerIssuerPolicy() {
            @Override
            public Decision decide(String issuer, KeycloakSystem system) {
                throw new IllegalStateException("directory down");
            }
        };
        assertTrue(new CallerIssuerPolicies(List.of(broken)).refusal("https://sso-b.example/realms/x", B, OWN)
            .isPresent());
    }
}
