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
        assertEquals(Optional.empty(),
                CallerIssuerPolicies.builtIn().refusal("https://sso-a.example/realms/other", trusting, own),
                "trusted by base: every realm of that Keycloak");
        assertTrue(CallerIssuerPolicies.builtIn().refusal("https://sso-c.example/realms/x", trusting, own).isPresent());
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
