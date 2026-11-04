package org.keycloak.mcp.server.guard;

import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.keycloak.mcp.catalog.Category;
import org.keycloak.mcp.catalog.ToolResult;
import org.keycloak.mcp.catalog.ToolSpec;
import org.keycloak.mcp.keycloak.AccessTokenSource;
import org.keycloak.mcp.server.Fixtures;
import org.keycloak.mcp.server.catalog.ToolCatalog;
import org.keycloak.mcp.spi.AccessCheck;
import org.keycloak.mcp.spi.Caller;
import org.keycloak.mcp.spi.Delegation;

import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AccessPolicyTest {

    private final ToolCatalog catalog = Fixtures.catalog(null);

    private static Map<String, Object> payload(ToolResult r) {
        return new JsonObject(r.toJson()).getMap();
    }

    private static RoleDiscovery discovery(String authRealm, JsonObject resourceAccess) {
        String token = GrantedRolesTest.jwt(new JsonObject().put("resource_access", resourceAccess));
        return new RoleDiscovery(new AccessTokenSource() {
            @Override
            public String accessToken() {
                return token;
            }

            @Override
            public String authRealm() {
                return authRealm;
            }
        }, true);
    }

    @Test
    void deniedAndAllowedToolsAndCategories() {
        ToolSpec search = catalog.get("keycloak_user_search").orElseThrow();
        ToolSpec delete = catalog.get("keycloak_user_delete").orElseThrow();
        ToolSpec sync = catalog.get("keycloak_federation_sync").orElseThrow();

        AccessPolicy denied = new AccessPolicy(false, List.of(), List.of(), List.of("keycloak_user_delete"), List.of(),
                null);
        assertTrue(denied.permits(search));
        assertFalse(denied.permits(delete));
        assertEquals("tool_not_allowed", payload(denied.forbids(delete, "demo").orElseThrow()).get("error"));

        AccessPolicy allowed = new AccessPolicy(false, List.of(), List.of("user_search", "User-Delete"), List.of(),
                List.of(), null);
        assertTrue(allowed.permits(search));
        assertTrue(allowed.permits(delete));
        assertFalse(allowed.permits(sync));

        AccessPolicy cats = new AccessPolicy(false, List.of(), List.of(), List.of(), List.of("users"), null);
        assertTrue(cats.permits(search));
        assertFalse(cats.permits(sync));
        assertEquals(Category.FEDERATION, sync.category());
    }

    @Test
    void rolesHideAndForbid() {
        ToolSpec search = ToolSpec.builder("keycloak_x_search")
            .title("s")
            .description("d")
            .category(Category.USERS)
            .read()
            .roles("view-users")
            .handler(c -> ToolResult.ok(""))
            .build();
        ToolSpec disable = ToolSpec.builder("keycloak_x_disable")
            .title("s")
            .description("d")
            .category(Category.USERS)
            .write()
            .roles("manage-users")
            .handler(c -> ToolResult.ok(""))
            .build();
        RoleDiscovery roles = discovery("demo", GrantedRolesTest.resourceAccess("realm-management", "view-users"));
        AccessPolicy policy = new AccessPolicy(false, List.of(), List.of(), List.of(), List.of(), roles);

        // nothing known yet: peek-based visibility does not block or hide
        assertTrue(policy.visible(disable));
        // blocking variant discovers roles
        assertTrue(policy.visibleNow(search));
        assertFalse(policy.visibleNow(disable));
        assertFalse(policy.visible(disable));

        assertTrue(policy.forbids(search, "demo").isEmpty());
        Map<String, Object> forbidden = payload(policy.forbids(disable, "demo").orElseThrow());
        assertEquals("forbidden", forbidden.get("error"));
        assertEquals(List.of("manage-users"), forbidden.get("missingRoles"));
        Map<String, Object> otherRealm = payload(policy.forbids(search, "other").orElseThrow());
        assertEquals("forbidden", otherRealm.get("error"));
        assertEquals(List.of("demo"), otherRealm.get("realmsWithRoles"));
    }

    @Test
    void unknownRolesNeverFilter() {
        ToolSpec disable = ToolSpec.builder("keycloak_x_disable")
            .title("s")
            .description("d")
            .category(Category.USERS)
            .write()
            .roles("manage-users")
            .handler(c -> ToolResult.ok(""))
            .build();
        RoleDiscovery roles = discovery("demo",
                new JsonObject().put("account", new JsonObject().put("roles", new JsonArray().add("view-profile"))));
        AccessPolicy policy = new AccessPolicy(false, List.of(), List.of(), List.of(), List.of(), roles);
        assertTrue(policy.visibleNow(disable));
        assertTrue(policy.forbids(disable, "demo").isEmpty());
        assertEquals(Set.of(), roles.get().realms());
    }

    private static ToolSpec.Builder spec(String name) {
        return ToolSpec.builder(name)
            .title("t")
            .description("d")
            .category(Category.USERS)
            .write()
            .schema(org.keycloak.mcp.catalog.InputSchema.builder().string("id", "id"))
            .handler(c -> ToolResult.ok(""));
    }

    @Test
    void perToolAccessChecksRunAfterRolesWithValidatedArgs() {
        ToolSpec guarded = spec("keycloak_x_delete").access(ctx -> "root".equals(ctx.arg("id"))
                ? AccessCheck.Decision.deny("protected_user", "root cannot be touched") : AccessCheck.Decision.allow())
            .access(ctx -> ctx.realm().equals("demo") ? AccessCheck.Decision.allow()
                    : AccessCheck.Decision.deny("only realm demo"))
            .build();
        AccessPolicy policy = new AccessPolicy(false, List.of());
        assertTrue(policy.forbids(guarded, "demo", Map.of("id", "bob"), InvocationContext.none()).isEmpty());
        Map<String, Object> denied = payload(
                policy.forbids(guarded, "demo", Map.of("id", "root"), InvocationContext.none()).orElseThrow());
        assertEquals("protected_user", denied.get("error"));
        assertEquals("root cannot be touched", denied.get("message"));
        assertEquals("access_denied",
                payload(policy.forbids(guarded, "other", Map.of("id", "bob"), InvocationContext.none()).orElseThrow())
                    .get("error"));
        // a throwing check denies instead of allowing
        ToolSpec broken = spec("keycloak_x_broken").access(ctx -> {
            throw new IllegalStateException("boom");
        }).build();
        assertEquals("access_check_failed",
                payload(policy.forbids(broken, "demo", Map.of(), InvocationContext.none()).orElseThrow()).get("error"));
    }

    @Test
    void globalChecksSeeTheCaller() {
        AccessCheck businessHours = ctx -> ctx.caller().isAnonymous() && !ctx.tool().isReadOnly()
                ? AccessCheck.Decision.deny("needs_identity", "writes need an identified caller")
                : AccessCheck.Decision.allow();
        AccessPolicy policy = new AccessPolicy(false, List.of(), List.of(), List.of(), List.of(), null,
                List.of(businessHours));
        ToolSpec write = spec("keycloak_x_write").build();
        assertEquals("needs_identity",
                payload(policy.forbids(write, "demo", Map.of(), InvocationContext.none()).orElseThrow()).get("error"));
        InvocationContext asAlice = InvocationContext.none().withCaller(Caller.of("sub-1", "alice", "demo", Set.of()));
        assertTrue(policy.forbids(write, "demo", Map.of(), asAlice).isEmpty());
    }

    @Test
    void delegationDeclarations() {
        AccessPolicy policy = new AccessPolicy(false, List.of());
        ToolSpec forbidden = spec("keycloak_x_secret").delegation(Delegation.FORBIDDEN).build();
        ToolSpec required = spec("keycloak_x_support").delegation(Delegation.REQUIRED).build();
        ToolSpec allowed = spec("keycloak_x_any").build();
        InvocationContext serviceAccount = InvocationContext.none();
        InvocationContext delegated = InvocationContext.none()
            .withCaller(Caller.delegated("sub-1", "alice", "demo", Set.of()));

        assertTrue(policy.forbids(forbidden, "demo", Map.of(), serviceAccount).isEmpty());
        assertEquals("delegation_not_allowed",
                payload(policy.forbids(forbidden, "demo", Map.of(), delegated).orElseThrow()).get("error"));
        assertEquals("delegation_required",
                payload(policy.forbids(required, "demo", Map.of(), serviceAccount).orElseThrow()).get("error"));
        assertTrue(policy.forbids(required, "demo", Map.of(), delegated).isEmpty());
        assertTrue(policy.forbids(allowed, "demo", Map.of(), delegated).isEmpty());
        assertTrue(policy.forbids(allowed, "demo", Map.of(), serviceAccount).isEmpty());
    }
}
