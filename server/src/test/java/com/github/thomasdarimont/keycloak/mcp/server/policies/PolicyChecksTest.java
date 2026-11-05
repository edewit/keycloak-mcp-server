package com.github.thomasdarimont.keycloak.mcp.server.policies;

import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;

import com.github.thomasdarimont.keycloak.mcp.access.AccessCheck;
import com.github.thomasdarimont.keycloak.mcp.access.Caller;
import com.github.thomasdarimont.keycloak.mcp.access.GrantedRoles;
import com.github.thomasdarimont.keycloak.mcp.catalog.Category;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolResult;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolSpec;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PolicyChecksTest {

    static final Caller ALICE = Caller.of("id-alice", "alice", "demo", Set.of("realm:group-manager"));
    static final Caller EVE = Caller.of("id-eve", "eve", "demo", Set.of());
    static final Caller ROOT = Caller.of("id-root", "root", "demo", Set.of("realm:admin"));
    static final Caller OTHER_REALM = Caller.of("id-x", "x", "other", Set.of());

    final FakeDirectory dir = new FakeDirectory()
        .user("alice", Set.of("realm:group-manager", "realm:editor", "realm:viewer", "app.user"), List.of("/team-a"),
                Set.of("org-1"))
        .user("bob", Set.of("realm:admin", "realm:viewer"), List.of("/team-b"), Set.of("org-2"))
        .user("carol", Set.of("realm:viewer"), List.of(), Set.of("org-1"))
        .user("eve", Set.of("realm:viewer"), List.of("/team-b"), Set.of("org-2"))
        .role("realm:viewer", Set.of("realm:viewer"))
        .role("realm:editor", Set.of("realm:editor", "realm:viewer"))
        .role("realm:admin", Set.of("realm:admin", "realm:viewer", "realm:editor", "app.admin"))
        .role("app.user", Set.of("app.user"))
        .group("/team-a", Set.of("realm:viewer"), Set.of("org-1"))
        .group("/team-a/dev", Set.of("realm:editor", "realm:viewer"), Set.of("org-1"))
        .group("/team-b", Set.of("realm:viewer"), Set.of("org-2"))
        .group("/admins", Set.of("realm:admin"), Set.of());

    static ToolSpec tool(String name, String... params) {
        var schema = com.github.thomasdarimont.keycloak.mcp.catalog.InputSchema.builder();
        for (String p : params) {
            schema.string(p, p);
        }
        return ToolSpec.builder(name)
            .title("t")
            .description("d")
            .category(Category.GROUPS)
            .write()
            .schema(schema)
            .handler(c -> ToolResult.ok(""))
            .build();
    }

    static AccessCheck.Context ctx(ToolSpec tool, Caller caller, Map<String, Object> args) {
        return new AccessCheck.Context(tool, "demo", args, GrantedRoles.UNKNOWN, caller);
    }

    PolicySettings settings(PolicySettings.GroupScope scope, String managerRole, boolean denyAnonymous) {
        return new PolicySettings(scope, managerRole, true, denyAnonymous, Set.of("realm:admin"));
    }

    @Test
    void groupScopeByMembership() {
        GroupScopeCheck check = new GroupScopeCheck(dir,
                settings(PolicySettings.GroupScope.GROUP, "realm:group-manager", false));
        ToolSpec members = tool("keycloak_group_members_list", "groupId");
        assertTrue(check.check(ctx(members, ALICE, Map.of("groupId", "/team-a"))).allowed());
        assertTrue(check.check(ctx(members, ALICE, Map.of("groupId", "/team-a/dev"))).allowed(), "subgroup");
        assertTrue(check.check(ctx(members, ALICE, Map.of("groupId", "dev"))).allowed(), "by name");
        assertEquals("group_out_of_scope", check.check(ctx(members, ALICE, Map.of("groupId", "/team-b"))).code());
        assertEquals("manager_role_required", check.check(ctx(members, EVE, Map.of("groupId", "/team-b"))).code());
        assertEquals("group_out_of_scope",
                check.check(ctx(tool("keycloak_group_create", "name", "parentId"), ALICE, Map.of("name", "x"))).code());
        assertTrue(check
            .check(ctx(tool("keycloak_group_create", "name", "parentId"), ALICE,
                    Map.of("name", "x", "parentId", "/team-a")))
            .allowed());
        // tools outside the group set are untouched
        assertTrue(check.check(ctx(tool("keycloak_user_get", "id"), EVE, Map.of("id", "bob"))).allowed());
        // unknown group: let the tool report not_found
        assertTrue(check.check(ctx(members, ALICE, Map.of("groupId", "/nope"))).allowed());
    }

    @Test
    void groupScopeByOrganization() {
        GroupScopeCheck check = new GroupScopeCheck(dir, settings(PolicySettings.GroupScope.ORGANIZATION, null, false));
        ToolSpec add = tool("keycloak_group_member_add", "groupId", "userId");
        assertTrue(check.check(ctx(add, ALICE, Map.of("groupId", "/team-a/dev", "userId", "carol"))).allowed());
        assertEquals("group_out_of_scope",
                check.check(ctx(add, ALICE, Map.of("groupId", "/team-b", "userId", "carol"))).code());
        assertEquals("group_out_of_scope",
                check.check(ctx(add, ALICE, Map.of("groupId", "/admins", "userId", "carol"))).code());
    }

    @Test
    void anonymousSuperAndForeignCallers() {
        GroupScopeCheck allow = new GroupScopeCheck(dir, settings(PolicySettings.GroupScope.GROUP, null, false));
        GroupScopeCheck deny = new GroupScopeCheck(dir, settings(PolicySettings.GroupScope.GROUP, null, true));
        ToolSpec members = tool("keycloak_group_members_list", "groupId");
        assertTrue(allow.check(ctx(members, Caller.NONE, Map.of("groupId", "/team-b"))).allowed());
        assertEquals("caller_required", deny.check(ctx(members, Caller.NONE, Map.of("groupId", "/team-b"))).code());
        assertTrue(deny.check(ctx(members, ROOT, Map.of("groupId", "/team-b"))).allowed(), "super role bypass");
        assertEquals("caller_foreign_realm",
                deny.check(ctx(members, OTHER_REALM, Map.of("groupId", "/team-b"))).code());
        Caller ghost = Caller.of("id-ghost", "ghost", "demo", Set.of());
        assertEquals("caller_unknown", deny.check(ctx(members, ghost, Map.of("groupId", "/team-b"))).code());
    }

    @Test
    void noEscalationOnGrants() {
        NoEscalationCheck check = new NoEscalationCheck(dir, settings(PolicySettings.GroupScope.OFF, null, false));
        ToolSpec assign = tool("keycloak_user_role_assign", "userId", "role");
        assertTrue(check.check(ctx(assign, ALICE, Map.of("userId", "carol", "role", "viewer"))).allowed());
        assertTrue(check.check(ctx(assign, ALICE, Map.of("userId", "carol", "role", "editor"))).allowed());
        AccessCheck.Decision d = check.check(ctx(assign, ALICE, Map.of("userId", "carol", "role", "admin")));
        assertEquals("privilege_escalation", d.code());
        assertTrue(d.message().contains("app.admin"), d.message());
        assertEquals("self_grant", check.check(ctx(assign, ALICE, Map.of("userId", "alice", "role", "viewer"))).code());
        // unknown role: nothing to grant, tool will say not_found
        assertTrue(check.check(ctx(assign, ALICE, Map.of("userId", "carol", "role", "nope"))).allowed());

        ToolSpec clientAssign = tool("keycloak_user_client_role_assign", "userId", "clientId", "role");
        assertTrue(check.check(ctx(clientAssign, ALICE, Map.of("userId", "carol", "clientId", "app", "role", "user")))
            .allowed());

        ToolSpec join = tool("keycloak_group_member_add", "groupId", "userId");
        assertTrue(check.check(ctx(join, ALICE, Map.of("groupId", "/team-a/dev", "userId", "carol"))).allowed());
        assertEquals("privilege_escalation",
                check.check(ctx(join, ALICE, Map.of("groupId", "/admins", "userId", "carol"))).code());

        ToolSpec groupRole = tool("keycloak_group_role_assign", "groupId", "role");
        assertEquals("privilege_escalation",
                check.check(ctx(groupRole, ALICE, Map.of("groupId", "/team-a", "role", "admin"))).code());
    }

    @Test
    void noEscalationOnManagingOutrankingUsers() {
        NoEscalationCheck check = new NoEscalationCheck(dir, settings(PolicySettings.GroupScope.OFF, null, false));
        ToolSpec disable = tool("keycloak_user_set_enabled", "id", "enabled");
        assertTrue(check.check(ctx(disable, ALICE, Map.of("id", "carol", "enabled", false))).allowed());
        AccessCheck.Decision d = check.check(ctx(disable, ALICE, Map.of("id", "bob", "enabled", false)));
        assertEquals("target_outranks_caller", d.code());
        assertTrue(d.message().contains("realm:admin"), d.message());
        assertEquals("target_outranks_caller",
                check
                    .check(ctx(tool("keycloak_user_reset_password", "id", "password"), ALICE,
                            Map.of("id", "bob", "password", "x")))
                    .code());
        // the super admin may do anything, anonymous is skipped
        assertTrue(check.check(ctx(disable, ROOT, Map.of("id", "bob", "enabled", false))).allowed());
        assertTrue(check.check(ctx(disable, Caller.NONE, Map.of("id", "bob", "enabled", false))).allowed());
        // reads are never affected
        assertTrue(check.check(ctx(tool("keycloak_user_get", "id"), EVE, Map.of("id", "bob"))).allowed());
    }

    @Test
    void providerIsSilentWhenDisabled() {
        assertTrue(new PolicyToolProvider(dir, PolicySettings.DISABLED).accessChecks(null).isEmpty());
        assertEquals(2,
                new PolicyToolProvider(dir, settings(PolicySettings.GroupScope.GROUP, null, false)).accessChecks(null)
                    .size());
    }

    @Test
    void ancestorPaths() {
        assertEquals(List.of("/a", "/a/b", "/a/b/c"), KeycloakDirectory.ancestorPaths("/a/b/c"));
    }
}
