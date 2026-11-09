package com.github.thomasdarimont.keycloak.mcp.backend.guard;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.Test;

import com.github.thomasdarimont.keycloak.mcp.access.GrantedRoles;
import com.github.thomasdarimont.keycloak.mcp.access.RoleRef;

import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class GrantedRolesTest {

    static String jwt(JsonObject payload) {
        Base64.Encoder b64 = Base64.getUrlEncoder().withoutPadding();
        return b64.encodeToString("{\"alg\":\"none\"}".getBytes(StandardCharsets.UTF_8)) + "."
                + b64.encodeToString(payload.encode().getBytes(StandardCharsets.UTF_8)) + ".sig";
    }

    static JsonObject resourceAccess(String client, String... roles) {
        return new JsonObject().put(client, new JsonObject().put("roles", new JsonArray(List.of(roles))));
    }

    @Test
    void masterAdminIsSuperAdmin() {
        GrantedRoles g = GrantedRoles.fromToken(
                jwt(new JsonObject().put("realm_access", new JsonObject().put("roles", new JsonArray().add("admin")))),
                "master");
        assertTrue(g.known());
        assertTrue(g.superAdmin());
        assertTrue(g.permits("anything", Set.of("manage-realm")));
        assertTrue(g.reaches("demo"));
    }

    @Test
    void realmManagementRolesBelongToTheAuthRealm() {
        GrantedRoles g = GrantedRoles.fromToken(jwt(new JsonObject().put("resource_access",
                resourceAccess("realm-management", "view-users", "view-clients"))), "demo");
        assertTrue(g.known());
        assertFalse(g.superAdmin());
        assertEquals(Set.of("demo"), g.realms());
        assertTrue(g.permits("demo", Set.of("view-users")));
        assertTrue(g.permits("demo", Set.of("query-users")), "view implies query");
        assertFalse(g.permits("demo", Set.of("manage-users")));
        assertEquals(Set.of("manage-users"), g.missing("demo", Set.of("manage-users", "view-clients")));
        assertFalse(g.reaches("other"));
        assertFalse(g.permits("other", Set.of("view-users")));
        assertTrue(g.permitsAnyRealm(Set.of("view-clients")));
        assertFalse(g.permitsAnyRealm(Set.of("manage-clients")));
    }

    @Test
    void masterClientRolesMapToTargetRealms() {
        JsonObject ra = resourceAccess("demo-realm", "manage-users")
            .mergeIn(resourceAccess("other-realm", "view-realm"))
            .mergeIn(resourceAccess("account", "manage-account"));
        GrantedRoles g = GrantedRoles.fromToken(jwt(new JsonObject().put("resource_access", ra)), "master");
        assertEquals(Set.of("demo", "other"), g.realms());
        assertTrue(g.permits("demo", Set.of("view-users")), "manage implies view");
        assertTrue(g.permits("other", Set.of("query-realms")));
        assertFalse(g.permits("other", Set.of("manage-realm")));
    }

    @Test
    void realmAdminCompositeSatisfiesEverything() {
        GrantedRoles g = GrantedRoles.fromToken(
                jwt(new JsonObject().put("resource_access", resourceAccess("realm-management", "realm-admin"))),
                "demo");
        assertTrue(g.permits("demo", Set.of("manage-identity-providers", "view-events")));
    }

    @Test
    void tokensWithoutAdminRolesAreUnknownAndNeverBlock() {
        GrantedRoles g = GrantedRoles
            .fromToken(jwt(new JsonObject().put("resource_access", resourceAccess("account", "view-profile"))), "demo");
        assertFalse(g.known());
        assertTrue(g.permits("demo", Set.of("manage-realm")));
        assertTrue(g.reaches("whatever"));
        assertFalse(GrantedRoles.fromToken(null, "demo").known());
        assertFalse(GrantedRoles.fromToken("garbage", "demo").known());
    }

    @Test
    void roleRefSyntax() {
        assertEquals(new RoleRef(RoleRef.Kind.REALM_MANAGEMENT, "realm-management", "view-users"),
                RoleRef.parse("view-users"));
        assertEquals(new RoleRef(RoleRef.Kind.REALM_MANAGEMENT, "realm-management", "view-users"),
                RoleRef.parse("realm-management.view-users"));
        assertEquals(new RoleRef(RoleRef.Kind.CLIENT, "com.acme.app", "auditor"),
                RoleRef.parse("com.acme.app.auditor"));
        assertEquals(new RoleRef(RoleRef.Kind.REALM, null, "offline_access"), RoleRef.parse("realm:offline_access"));
        assertEquals("my-app.auditor", RoleRef.parse("my-app.auditor").toString());
    }

    @Test
    void customClientAndRealmRolesInTheAuthRealm() {
        JsonObject ra = resourceAccess("realm-management", "view-users").mergeIn(resourceAccess("my-app", "auditor"));
        GrantedRoles g = GrantedRoles.fromToken(jwt(new JsonObject().put("resource_access", ra)
            .put("realm_access", new JsonObject().put("roles", new JsonArray().add("support")))), "demo");
        assertTrue(g.permits("demo", Set.of("my-app.auditor")));
        assertTrue(g.permits("demo", Set.of("realm-management.view-users", "realm:support")));
        assertFalse(g.permits("demo", Set.of("my-app.admin")));
        assertFalse(g.permits("demo", Set.of("realm:admin")));
        assertEquals(Set.of("my-app.admin"), g.missing("demo", Set.of("view-users", "my-app.admin")));
        // custom roles are not visible for other realms managed from master
        assertFalse(g.permits("other", Set.of("my-app.auditor")));
        assertTrue(g.permitsAnyRealm(Set.of("realm:support")));
    }

    @Test
    void customRolesAloneLeaveTheTokenUnknown() {
        GrantedRoles g = GrantedRoles
            .fromToken(jwt(new JsonObject().put("resource_access", resourceAccess("my-app", "auditor"))), "demo");
        assertFalse(g.known(), "no admin roles: filtering stays off");
        assertTrue(g.permits("demo", Set.of("my-app.admin")));
    }
}
