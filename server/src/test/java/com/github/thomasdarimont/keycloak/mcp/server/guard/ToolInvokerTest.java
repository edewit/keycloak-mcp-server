package com.github.thomasdarimont.keycloak.mcp.server.guard;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import com.github.thomasdarimont.keycloak.mcp.catalog.Category;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolException;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolResult;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolSpec;
import com.github.thomasdarimont.keycloak.mcp.confirm.Confirmer;
import com.github.thomasdarimont.keycloak.mcp.server.Fixtures;
import com.github.thomasdarimont.keycloak.mcp.server.catalog.ToolCatalog;

import io.vertx.core.json.JsonObject;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ToolInvokerTest {

    private final ToolCatalog catalog = Fixtures.catalog(null);
    private final InvocationContext ctx = InvocationContext.none();

    private ToolInvoker invoker(boolean readOnly, List<String> realms, Confirmer confirmer) {
        return new ToolInvoker(catalog, new AccessPolicy(readOnly, realms), confirmer, 50);
    }

    private static Confirmer fixed(Confirmer.Decision d) {
        return req -> d;
    }

    private static Map<String, Object> payload(ToolResult r) {
        return new JsonObject(r.toJson()).getMap();
    }

    @Test
    void happyPathResolvesRealmAndClampsMax() {
        ToolSpec spec = catalog.get("keycloak_user_search").orElseThrow();
        ToolResult r = invoker(false, List.of(), fixed(Confirmer.Decision.CONFIRMED)).invoke(spec,
                Map.of("realm", "demo", "max", 999, "search", "bob"), false, ctx);
        assertFalse(r.isError(), r.toJson());
        String json = r.toJson();
        assertTrue(json.contains("\"realm\":\"demo\""), json);
        assertTrue(json.contains("\"max\":50"), json);
    }

    @Test
    void realmRequiredWithoutDefault() {
        ToolSpec spec = catalog.get("keycloak_user_search").orElseThrow();
        ToolResult r = invoker(false, List.of(), fixed(Confirmer.Decision.CONFIRMED)).invoke(spec, Map.of(), false,
                ctx);
        assertTrue(r.isError());
        assertEquals("invalid_arguments", payload(r).get("error"));
        ToolCatalog withDefault = Fixtures.catalog("demo");
        ToolResult ok = new ToolInvoker(withDefault, new AccessPolicy(false, List.of()),
                fixed(Confirmer.Decision.CONFIRMED), 50)
            .invoke(withDefault.get("keycloak_user_search").orElseThrow(), Map.of(), false, ctx);
        assertFalse(ok.isError());
        assertTrue(ok.toJson().contains("\"realm\":\"demo\""));
    }

    @Test
    void realmAllowList() {
        ToolSpec spec = catalog.get("keycloak_user_search").orElseThrow();
        ToolResult r = invoker(false, List.of("a", "b"), fixed(Confirmer.Decision.CONFIRMED)).invoke(spec,
                Map.of("realm", "c"), false, ctx);
        assertTrue(r.isError());
        assertEquals("realm_not_allowed", payload(r).get("error"));
        assertEquals(List.of("a", "b"), ((List<?>) payload(r).get("allowed")).stream().sorted().toList());
    }

    @Test
    void readOnlyBlocksWrites() {
        ToolSpec spec = catalog.get("keycloak_user_set_enabled").orElseThrow();
        ToolResult r = invoker(true, List.of(), fixed(Confirmer.Decision.CONFIRMED)).invoke(spec,
                Map.of("realm", "demo", "id", "1", "enabled", false), false, ctx);
        assertEquals("read_only_mode", payload(r).get("error"));
        ToolResult read = invoker(true, List.of(), fixed(Confirmer.Decision.CONFIRMED))
            .invoke(catalog.get("keycloak_user_search").orElseThrow(), Map.of("realm", "demo"), false, ctx);
        assertFalse(read.isError());
    }

    @Test
    void invalidArgumentsReturnProblemsAndSchema() {
        ToolSpec spec = catalog.get("keycloak_user_set_enabled").orElseThrow();
        ToolResult r = invoker(false, List.of(), fixed(Confirmer.Decision.CONFIRMED)).invoke(spec,
                Map.of("realm", "demo", "id", "1"), false, ctx);
        Map<String, Object> p = payload(r);
        assertEquals("invalid_arguments", p.get("error"));
        assertEquals("enabled", ((Map<?, ?>) ((List<?>) p.get("problems")).get(0)).get("field"));
        assertTrue(p.containsKey("inputSchema"));
    }

    @Test
    void destructiveNeedsConfirmation() {
        ToolSpec spec = catalog.get("keycloak_user_delete").orElseThrow();
        Map<String, Object> args = Map.of("realm", "demo", "id", "1");
        assertEquals("confirmation_required",
                payload(invoker(false, List.of(), fixed(Confirmer.Decision.CONFIRMATION_REQUIRED)).invoke(spec, args,
                        false, ctx))
                    .get("error"));
        assertEquals("cancelled",
                payload(invoker(false, List.of(), fixed(Confirmer.Decision.DECLINED)).invoke(spec, args, false, ctx))
                    .get("error"));
        ToolResult ok = invoker(false, List.of(), fixed(Confirmer.Decision.CONFIRMED)).invoke(spec, args, false, ctx);
        assertFalse(ok.isError());
        assertEquals("deleted", payload(ok).get("message"));
    }

    @Test
    void defaultConfirmerWithoutElicitationUsesFlag() {
        ToolSpec spec = catalog.get("keycloak_user_delete").orElseThrow();
        DefaultConfirmer confirmer = new DefaultConfirmer();
        Map<String, Object> args = Map.of("realm", "demo", "id", "1");
        assertEquals("confirmation_required",
                payload(invoker(false, List.of(), confirmer).invoke(spec, args, false, ctx)).get("error"));
        assertFalse(invoker(false, List.of(), confirmer).invoke(spec, args, true, ctx).isError());
    }

    @Test
    void handlerExceptionsBecomeStructuredErrors() {
        ToolSpec failing = ToolSpec.builder("keycloak_boom")
            .title("Boom")
            .description("fails")
            .category(com.github.thomasdarimont.keycloak.mcp.catalog.Category.REALM)
            .global()
            .handler(call -> {
                throw new ToolException("not_found", "nope");
            })
            .build();
        ToolCatalog c = new ToolCatalog(List.of(failing), null, 10, List.of());
        ToolResult r = new ToolInvoker(c, new AccessPolicy(false, List.of()), fixed(Confirmer.Decision.CONFIRMED), 10)
            .invoke(failing, Map.of(), false, ctx);
        assertTrue(r.isError());
        assertEquals("not_found", payload(r).get("error"));
        assertEquals("nope", payload(r).get("message"));
    }

    @Test
    void routesToTheRequestedSystem() {
        com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystem a = new com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystem(
                "a", "http://a", com.github.thomasdarimont.keycloak.mcp.config.GrantType.PASSWORD,
                com.github.thomasdarimont.keycloak.mcp.config.ClientAuth.NONE, "master", java.util.Optional.empty(),
                java.util.Optional.empty(), java.util.Optional.of("admin"), java.util.Optional.of("admin"),
                java.util.Optional.of("demo"), java.util.Set.of(), java.util.Optional.empty());
        com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystem b = new com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystem(
                "b", "http://b", com.github.thomasdarimont.keycloak.mcp.config.GrantType.PASSWORD,
                com.github.thomasdarimont.keycloak.mcp.config.ClientAuth.NONE, "master", java.util.Optional.empty(),
                java.util.Optional.empty(), java.util.Optional.of("admin"), java.util.Optional.of("admin"),
                java.util.Optional.of("b-default"), java.util.Set.of("only-b", "b-default"),
                java.util.Optional.empty());
        com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystems systems = new com.github.thomasdarimont.keycloak.mcp.server.keycloak.DefaultKeycloakSystems(
                List.of(a, b), "a", null);
        ToolSpec echo = ToolSpec.builder("keycloak_echo")
            .title("e")
            .description("d")
            .category(com.github.thomasdarimont.keycloak.mcp.catalog.Category.REALM)
            .handler(call -> ToolResult
                .ok(Map.of("system", call.system(), "admin", call.kc().name(), "realm", call.realm())))
            .build();
        // both systems have a default realm, so the realm argument is optional and
        // resolved per system
        ToolCatalog cat = new ToolCatalog(List.of(echo), "(per system)", 10, List.of(), "", List.of("a", "b"), "a");
        AccessPolicy policy = new AccessPolicy(false, List.of(), List.of(), List.of(), List.of(), null, List.of(),
                name -> systems.get(name).system().allowedRealms());
        ToolInvoker inv = new ToolInvoker(cat, policy, fixed(Confirmer.Decision.CONFIRMED), 10, systems);
        ToolSpec spec = cat.get("keycloak_echo").orElseThrow();

        Map<String, Object> viaDefault = payload(inv.invoke(spec, Map.of(), false, ctx));
        assertEquals("a", viaDefault.get("system"));
        assertEquals("demo", viaDefault.get("realm"), "default realm of system a");
        Map<String, Object> viaB = payload(inv.invoke(spec, Map.of("system", "b", "realm", "only-b"), false, ctx));
        assertEquals("b", viaB.get("admin"));
        assertEquals("b-default", payload(inv.invoke(spec, Map.of("system", "b"), false, ctx)).get("realm"));
        assertEquals("realm_not_allowed",
                payload(inv.invoke(spec, Map.of("system", "b", "realm", "x"), false, ctx)).get("error"));
        assertEquals("invalid_arguments",
                payload(inv.invoke(spec, Map.of("system", "nope", "realm", "x"), false, ctx)).get("error"),
                "enum rejects unknown systems before dispatch");

        com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystems noDefault = new com.github.thomasdarimont.keycloak.mcp.server.keycloak.DefaultKeycloakSystems(
                List.of(a, b), null, null);
        ToolCatalog cat2 = new ToolCatalog(List.of(echo), null, 10, List.of(), "", List.of("a", "b"), null);
        ToolInvoker inv2 = new ToolInvoker(cat2, policy, fixed(Confirmer.Decision.CONFIRMED), 10, noDefault);
        assertEquals("invalid_arguments",
                payload(inv2.invoke(cat2.get("keycloak_echo").orElseThrow(), Map.of("realm", "demo"), false, ctx))
                    .get("error"),
                "system is required in the schema when there is no default");
    }

    @Test
    void boundEntriesPinSystemAndRealm() {
        com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystem a = new com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystem(
                "a", "http://a", com.github.thomasdarimont.keycloak.mcp.config.GrantType.PASSWORD,
                com.github.thomasdarimont.keycloak.mcp.config.ClientAuth.NONE, "master", java.util.Optional.empty(),
                java.util.Optional.empty(), java.util.Optional.of("admin"), java.util.Optional.of("admin"),
                java.util.Optional.of("demo"), java.util.Set.of(), java.util.Optional.empty());
        com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystem b = new com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystem(
                "b", "http://b", com.github.thomasdarimont.keycloak.mcp.config.GrantType.PASSWORD,
                com.github.thomasdarimont.keycloak.mcp.config.ClientAuth.NONE, "master", java.util.Optional.empty(),
                java.util.Optional.empty(), java.util.Optional.of("admin"), java.util.Optional.of("admin"),
                java.util.Optional.of("b-default"), java.util.Set.of("only-b", "b-default"),
                java.util.Optional.empty());
        com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystems systems = new com.github.thomasdarimont.keycloak.mcp.server.keycloak.DefaultKeycloakSystems(
                List.of(a, b), "a", null);
        ToolSpec echo = ToolSpec.builder("keycloak_echo")
            .title("e")
            .description("d")
            .category(Category.USERS)
            .read()
            .handler(call -> ToolResult.ok(Map.of("system", call.system(), "realm", call.realm())))
            .build();
        ToolCatalog c = new ToolCatalog(List.of(echo), null, 50, List.of(), "", List.of("a", "b"), "a");
        ToolInvoker inv = new ToolInvoker(c, new AccessPolicy(false, List.of()), fixed(Confirmer.Decision.CONFIRMED),
                10, systems);

        InvocationContext onB = InvocationContext.none().withBinding(new EntryBinding("b", null));
        Map<String, Object> r = payload(inv.invoke(echo, Map.of("realm", "only-b"), false, onB));
        assertEquals("b", r.get("system"), "the entry decides, not the default system");
        Map<String, Object> mismatch = payload(inv.invoke(echo, Map.of("system", "a", "realm", "only-b"), false, onB));
        assertEquals("entry_mismatch", mismatch.get("error"), mismatch.toString());

        InvocationContext onBRealm = InvocationContext.none().withBinding(new EntryBinding("b", "only-b"));
        Map<String, Object> pinned = payload(inv.invoke(echo, Map.of(), false, onBRealm));
        assertEquals("only-b", pinned.get("realm"), pinned.toString());
        Map<String, Object> realmMismatch = payload(inv.invoke(echo, Map.of("realm", "b-default"), false, onBRealm));
        assertEquals("entry_mismatch", realmMismatch.get("error"), realmMismatch.toString());
        assertTrue(inv.hasSystem("b"));
        assertFalse(inv.hasSystem("nope"));
    }
}
