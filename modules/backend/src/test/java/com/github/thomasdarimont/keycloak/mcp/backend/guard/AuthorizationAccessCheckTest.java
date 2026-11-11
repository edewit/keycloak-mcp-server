package com.github.thomasdarimont.keycloak.mcp.backend.guard;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.junit.jupiter.api.Test;

import com.github.thomasdarimont.keycloak.mcp.access.AccessCheck;
import com.github.thomasdarimont.keycloak.mcp.access.AuthorizationEngine;
import com.github.thomasdarimont.keycloak.mcp.access.AuthorizationEngine.Request;
import com.github.thomasdarimont.keycloak.mcp.access.Caller;
import com.github.thomasdarimont.keycloak.mcp.access.GrantedRoles;
import com.github.thomasdarimont.keycloak.mcp.catalog.Category;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolResult;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolSpec;
import com.github.thomasdarimont.keycloak.mcp.keycloak.AuthorizationSettings;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystem;
import com.github.thomasdarimont.keycloak.mcp.keycloak.RealmSettings;

import io.vertx.core.json.JsonObject;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** No system loses its governance to an engine the server does not have. */
class AuthorizationAccessCheckTest {

    static final ToolSpec TOOL = ToolSpec.builder("keycloak_user_get")
        .title("t")
        .description("d")
        .category(Category.USERS)
        .read()
        .handler(c -> ToolResult.ok(""))
        .build();

    static final AuthorizationEngine AUTHZEN = new AuthorizationEngine() {
        @Override
        public String id() {
            return "authzen";
        }

        @Override
        public com.github.thomasdarimont.keycloak.mcp.access.AccessCheck.Decision decide(Request request) {
            return com.github.thomasdarimont.keycloak.mcp.access.AccessCheck.Decision.allow();
        }
    };

    static KeycloakSystem system(String name, String authorization, RealmSettings... realms) {
        KeycloakSystem.Builder b = KeycloakSystem.builder(name, "https://" + name + ".example")
            .authorization(AuthorizationSettings.fromJson(new JsonObject(authorization)));
        for (RealmSettings r : realms) {
            b.realm(r);
        }
        return b.build();
    }

    static AuthorizationAccessCheck guard(List<AuthorizationEngine> engines, KeycloakSystem... systems) {
        Map<String, KeycloakSystem> byName = new java.util.HashMap<>();
        for (KeycloakSystem s : systems) {
            byName.put(s.name(), s);
        }
        return new AuthorizationAccessCheck(() -> engines, n -> Optional.ofNullable(n == null ? null : byName.get(n)),
                () -> List.of(systems));
    }

    static AccessCheck.Decision call(AuthorizationAccessCheck g, String system, String realm) {
        return g.check(new AccessCheck.Context(TOOL, system, realm, Map.of(), GrantedRoles.UNKNOWN, Caller.NONE, null));
    }

    @Test
    void callsOfASystemNamingAMissingEngineAreDenied() {
        var opa = system("opa", "{\"acme-opa\": {\"endpoint\": \"https://opa\"}}");
        var fine = system("fine", "{\"authzen\": {\"url\": \"https://pdp\"}}");
        var g = guard(List.of(AUTHZEN), opa, fine);

        AccessCheck.Decision d = call(g, "opa", "acme");
        assertFalse(d.allowed());
        assertEquals("authorization_unavailable", d.code());
        assertTrue(call(g, "fine", "acme").allowed());
        assertTrue(call(g, "unknown", "acme").allowed());
    }

    @Test
    void aRealmThatSwitchesItOffNeedsNoEngine() {
        var opa = system("opa", "{\"acme-opa\": {}}",
                new RealmSettings("sandbox", AuthorizationSettings.fromJson(new JsonObject("{\"enabled\": false}"))));
        var g = guard(List.of(AUTHZEN), opa);

        assertTrue(call(g, "opa", "sandbox").allowed());
        assertFalse(call(g, "opa", "other").allowed());
    }

    @Test
    void switchedOnWithoutAnyEngineOnTheServer() {
        var on = system("on", "{\"enabled\": true}");

        assertFalse(call(guard(List.of(), on), "on", "acme").allowed());
        assertTrue(call(guard(List.of(AUTHZEN), on), "on", "acme").allowed(), "AuthZEN takes it");
    }

    @Test
    void configuredSystemsNamingMissingEnginesStopTheStart() {
        var bad = system("prod", "{}",
                new RealmSettings("acme", AuthorizationSettings.fromJson(new JsonObject("{\"vendor\": {}}"))));

        IllegalStateException e = assertThrows(IllegalStateException.class,
                () -> guard(List.of(AUTHZEN), bad).runStartupChecks());
        assertTrue(e.getMessage().contains("vendor"), e.getMessage());
        guard(List.of(AUTHZEN), system("ok", "{\"authzen\": {}}")).runStartupChecks();
    }

    /** An engine that answers what it is told and remembers what it saw. */
    static final class Scripted implements AuthorizationEngine {
        final String id;
        final boolean byDefault;
        final java.util.function.Function<Request, AccessCheck.Decision> answer;
        final List<Request> seen = new java.util.concurrent.CopyOnWriteArrayList<>();

        Scripted(String id, boolean byDefault, java.util.function.Function<Request, AccessCheck.Decision> answer) {
            this.id = id;
            this.byDefault = byDefault;
            this.answer = answer;
        }

        @Override
        public String id() {
            return id;
        }

        @Override
        public boolean evaluatesByDefault() {
            return byDefault;
        }

        @Override
        public AccessCheck.Decision decide(Request request) {
            seen.add(request);
            return answer.apply(request);
        }
    }

    @Test
    void enginesDecideTheFirstDenialWins() {
        var yes = new Scripted("yes", false, r -> AccessCheck.Decision.allow());
        var no = new Scripted("no", false, r -> AccessCheck.Decision.deny("policy_denied", "no"));
        var both = system("both", "{\"enabled\": true}");

        AccessCheck.Decision d = call(guard(List.of(yes, no), both), "both", "acme");

        assertEquals("policy_denied", d.code());
        assertEquals(1, yes.seen.size());
        assertEquals(1, no.seen.size(), "naming none: every engine");
    }

    @Test
    void onlyTheNamedEnginesAndEachWithItsOwnSettings() {
        var a = new Scripted("a", false, r -> AccessCheck.Decision.allow());
        var b = new Scripted("b", false, r -> AccessCheck.Decision.allow());
        var named = system("named", "{\"enabled\": true, \"a\": {\"x\": \"1\"}}",
                new RealmSettings("acme", AuthorizationSettings.fromJson(new JsonObject("{\"a\": {\"x\": \"2\"}}"))));

        call(guard(List.of(a, b), named), "named", "acme");
        call(guard(List.of(a, b), named), "named", "other");

        assertTrue(b.seen.isEmpty());
        assertEquals("2", a.seen.getFirst().settings().get("x"), "the realm's over the system's");
        assertEquals("1", a.seen.get(1).settings().get("x"));
        assertEquals("named", a.seen.getFirst().system().orElseThrow().name());
    }

    @Test
    void eachEngineItsOwnDefault() {
        var eager = new Scripted("eager", true, r -> AccessCheck.Decision.allow());
        var lazy = new Scripted("lazy", false, r -> AccessCheck.Decision.allow());
        var silent = system("silent", "{}");

        call(guard(List.of(eager, lazy), silent), "silent", "acme");

        assertEquals(1, eager.seen.size());
        assertTrue(lazy.seen.isEmpty());
    }

    @Test
    void confirmationsAreHandedOnAndFailuresDeny() {
        var ask = new Scripted("ask", false, r -> AccessCheck.Decision.confirm("policy_confirmation", "confirm"));
        var boom = new Scripted("boom", false, r -> {
            throw new IllegalStateException("PDP client bug");
        });
        var s = system("s", "{\"enabled\": true, \"ask\": {}}");
        var t = system("t", "{\"enabled\": true, \"boom\": {}}");

        assertTrue(call(guard(List.of(ask, boom), s, t), "s", "acme").confirmation());
        AccessCheck.Decision failed = call(guard(List.of(ask, boom), s, t), "t", "acme");
        assertFalse(failed.allowed());
        assertEquals("authorization_unavailable", failed.code());
    }
}
