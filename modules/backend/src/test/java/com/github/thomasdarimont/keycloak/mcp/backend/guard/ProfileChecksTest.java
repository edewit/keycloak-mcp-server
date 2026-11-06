package com.github.thomasdarimont.keycloak.mcp.backend.guard;

import java.util.List;

import org.junit.jupiter.api.Test;

import com.github.thomasdarimont.keycloak.mcp.config.ExplicitTarget;
import com.github.thomasdarimont.keycloak.mcp.config.Profile;
import com.github.thomasdarimont.keycloak.mcp.config.ProfileCheck;
import com.github.thomasdarimont.keycloak.mcp.config.ProfileCheckContext;
import com.github.thomasdarimont.keycloak.mcp.spi.ProviderConfig;

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
        assertEquals(ExplicitTarget.WRITE, ExplicitTarget.parse("mutations"));
    }

    private static ProfileCheck check(String id, List<String> problems, List<String> warnings, boolean fail) {
        return new ProfileCheck() {
            @Override
            public String id() {
                return id;
            }

            @Override
            public List<String> problems(ProfileCheckContext ctx) {
                if (fail) {
                    throw new IllegalStateException("boom");
                }
                return ctx.shared() ? problems : List.of();
            }

            @Override
            public List<String> warnings(ProfileCheckContext ctx) {
                return warnings;
            }
        };
    }

    private static java.util.function.Function<String, ProfileCheckContext> contexts(Profile profile) {
        return id -> new ProfileCheckContext(profile, true, null, new ProviderConfig(id, java.util.Map.of()), null);
    }

    @Test
    void extensionChecksJoinTheBuiltInOnesTaggedWithTheirId() {
        var s = settings(Profile.SHARED, false, true, true, false, false, false, true);
        var findings = ProfileChecks.run(s,
                List.of(check("acme", List.of("the ticket URL must be https"), List.of("w1"), false),
                        check("quiet", List.of(), List.of(), false)),
                contexts(Profile.SHARED));
        assertEquals(List.of("kc-mcp.profile=shared needs authenticated callers: quarkus.oidc.tenant-enabled=true"
                + " (env QUARKUS_OIDC_TENANT_ENABLED) with quarkus.oidc.auth-server-url pointing at the realm that"
                + " issues the caller tokens", "[acme] the ticket URL must be https"), findings.problems());
        assertEquals(List.of("[acme] w1"), findings.warnings());
    }

    @Test
    void aFailingCheckStopsASharedServerAndOnlyWarnsALocalOne() {
        var ok = settings(Profile.SHARED, true, true, true, false, false, false, true);
        var shared = ProfileChecks.run(ok, List.of(check("flaky", List.of(), List.of(), true)),
                contexts(Profile.SHARED));
        assertEquals(1, shared.problems().size());
        assertTrue(shared.problems().get(0).startsWith("[flaky] the check failed"), shared.problems().toString());

        var local = ProfileChecks.run(settings(Profile.LOCAL, true, true, true, false, false, false, true),
                List.of(check("flaky", List.of(), List.of(), true)), contexts(Profile.LOCAL));
        assertTrue(local.problems().isEmpty());
        assertTrue(local.warnings().stream().anyMatch(w -> w.startsWith("[flaky] the check failed")),
                local.warnings().toString());
    }
}
