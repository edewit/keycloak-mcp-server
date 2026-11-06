package com.github.thomasdarimont.keycloak.mcp.backend.guard;

import java.util.List;

import org.junit.jupiter.api.Test;

import com.github.thomasdarimont.keycloak.mcp.config.Profile;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ProfileChecksTest {

    private static ProfileChecks.Settings settings(Profile profile, boolean oidc, boolean audience, boolean hosts,
            boolean adminEnabled, boolean adminIssuer, boolean adminAudience, boolean newSystems) {
        return new ProfileChecks.Settings(profile, oidc, audience, hosts, adminEnabled, adminIssuer, adminAudience,
                newSystems);
    }

    @Test
    void localNeverFails() {
        assertTrue(ProfileChecks.problems(settings(Profile.LOCAL, false, false, false, true, true, false, true))
            .isEmpty());
    }

    @Test
    void localWarnsAboutOpenRegistrationWithoutHostList() {
        List<String> w = ProfileChecks.warnings(settings(Profile.LOCAL, true, true, false, true, true, true, true));
        assertEquals(1, w.size(), w.toString());
        assertTrue(w.get(0).contains("kc-mcp.allowed-hosts"), w.get(0));
        assertTrue(
                ProfileChecks.warnings(settings(Profile.LOCAL, true, true, false, true, true, true, false)).isEmpty(),
                "closed registration");
        assertTrue(ProfileChecks.warnings(settings(Profile.LOCAL, true, true, true, true, true, true, true)).isEmpty(),
                "hosts listed");
    }

    @Test
    void sharedListsEveryMissingSetting() {
        List<String> p = ProfileChecks.problems(settings(Profile.SHARED, false, false, false, true, true, false, true));
        assertEquals(4, p.size(), p.toString());
        assertTrue(p.get(0).contains("quarkus.oidc.tenant-enabled"));
        assertTrue(p.get(1).contains("quarkus.oidc.token.audience"));
        assertTrue(p.get(2).contains("kc-mcp.allowed-hosts"));
        assertTrue(p.get(3).contains("kc-mcp.admin.audience"));
    }

    @Test
    void sharedPassesWhenConfigured() {
        assertTrue(
                ProfileChecks.problems(settings(Profile.SHARED, true, true, true, true, true, true, true)).isEmpty());
        assertTrue(
                ProfileChecks.problems(settings(Profile.SHARED, true, true, true, false, false, false, true)).isEmpty(),
                "admin API off: no admin audience needed");
        assertTrue(
                ProfileChecks.problems(settings(Profile.SHARED, true, true, true, true, false, false, true)).isEmpty(),
                "admin API with a static token only: no issuer, no audience needed");
        assertTrue(
                ProfileChecks.warnings(settings(Profile.SHARED, true, true, true, true, true, true, true)).isEmpty());
    }

    @Test
    void profileParsesAliases() {
        assertEquals(Profile.SHARED, Profile.parse("prod"));
        assertEquals(Profile.LOCAL, Profile.parse(" Local "));
        assertEquals(com.github.thomasdarimont.keycloak.mcp.config.ConfirmFallback.DENY,
                com.github.thomasdarimont.keycloak.mcp.config.ConfirmFallback.parse("elicitation-only"));
        assertEquals(com.github.thomasdarimont.keycloak.mcp.config.ExplicitTarget.WRITE,
                com.github.thomasdarimont.keycloak.mcp.config.ExplicitTarget.parse("mutations"));
    }
}
