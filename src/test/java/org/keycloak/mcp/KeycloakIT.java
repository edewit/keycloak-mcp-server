package org.keycloak.mcp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import io.quarkus.test.common.QuarkusTestResource;
import io.quarkus.test.junit.QuarkusTest;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

/**
 * Happy paths of the ported USERS / GROUPS / ROLES / REALM tools against a real Keycloak, driven through the MCP
 * endpoint in direct mode. Run with {@code ./mvnw verify -DskipITs=false}.
 */
@QuarkusTest
@QuarkusTestResource(value = KeycloakTestResource.class, restrictToAnnotatedClass = true)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class KeycloakIT {

    static final String REALM = "master";
    static McpClient mcp;
    static String userId;
    static String groupId;

    @BeforeEach
    void connect() {
        if (mcp == null) {
            mcp = new McpClient().initialize(false);
        }
    }

    static JsonObject call(String tool, JsonObject args) {
        JsonObject result = mcp.callTool(tool, args.put("realm", REALM));
        JsonObject body = McpClient.text(result);
        assertFalse(result.getBoolean("isError", false), tool + " -> " + body.encode());
        return body;
    }

    static JsonObject error(String tool, JsonObject args) {
        JsonObject result = mcp.callTool(tool, args.put("realm", REALM));
        assertTrue(result.getBoolean("isError", false), tool + " should fail");
        return McpClient.text(result);
    }

    @Test
    @Order(1)
    void serverInfoAndRealmConfig() {
        JsonObject info = McpClient.text(mcp.callTool("keycloak_server_info", new JsonObject()));
        assertTrue(info.getString("version").startsWith("26."), info.encode());
        JsonObject cfg = call("keycloak_realm_get_config", new JsonObject());
        assertEquals("master", cfg.getString("realm"));
        assertEquals("browser", cfg.getJsonObject("flows").getString("browserFlow"));
    }

    @Test
    @Order(2)
    void userLifecycle() {
        JsonObject created = call("keycloak_user_create", new JsonObject()
                .put("username", "alice").put("email", "alice@example.com").put("firstName", "Alice")
                .put("password", "secret1!").put("temporary", "true"));
        userId = created.getString("id");
        assertNotNull(userId);

        JsonObject dup = error("keycloak_user_create", new JsonObject().put("username", "alice"));
        assertEquals("conflict", dup.getString("error"));

        JsonObject search = call("keycloak_user_search", new JsonObject().put("search", "ali"));
        assertEquals("alice", search.getJsonArray("items").getJsonObject(0).getString("username"));
        JsonObject byEmail = call("keycloak_user_search", new JsonObject().put("email", "alice@example.com"));
        assertEquals(1, byEmail.getInteger("count"));

        // id or username both resolve
        JsonObject get = call("keycloak_user_get", new JsonObject().put("id", "alice"));
        assertEquals(userId, get.getString("id"));
        assertEquals("Alice", get.getString("firstName"));
        assertTrue(get.getJsonArray("requiredActions").contains("UPDATE_PASSWORD"));

        JsonObject upd = call("keycloak_user_update", new JsonObject().put("id", userId).put("lastName", "Liddell")
                .put("attributes", new JsonObject().put("department", "R&D")));
        assertTrue(upd.getJsonArray("changed").contains("attributes"));
        // a fresh KC 26 realm drops undeclared attributes (user profile); the tool must say so instead of lying
        assertTrue(upd.getString("warning", "").contains("department"), upd.encode());
        JsonObject get2 = call("keycloak_user_get", new JsonObject().put("id", userId));
        assertEquals("Liddell", get2.getString("lastName"));

        call("keycloak_user_set_enabled", new JsonObject().put("id", "alice").put("enabled", false));
        JsonObject disabled = call("keycloak_user_search", new JsonObject().put("username", "alice"));
        assertEquals(false, disabled.getJsonArray("items").getJsonObject(0).getBoolean("enabled"));
        call("keycloak_user_set_enabled", new JsonObject().put("id", "alice").put("enabled", "yes"));

        JsonObject missing = error("keycloak_user_get", new JsonObject().put("id", "nobody"));
        assertEquals("not_found", missing.getString("error"));

        call("keycloak_user_reset_password", new JsonObject().put("id", userId).put("password", "newpass1!")
                .put("confirm", true));
        JsonObject sessions = call("keycloak_user_sessions_list", new JsonObject().put("id", userId));
        assertEquals(0, sessions.getInteger("count"));
        call("keycloak_user_logout", new JsonObject().put("id", userId).put("confirm", true));
    }

    @Test
    @Order(3)
    void groupsAndMembership() {
        JsonObject g = call("keycloak_group_create", new JsonObject().put("name", "admins"));
        groupId = g.getString("id");
        assertEquals("/admins", g.getString("path"));
        JsonObject sub = call("keycloak_group_create", new JsonObject().put("name", "ops").put("parentId", "admins"));
        assertEquals("/admins/ops", sub.getString("path"));

        JsonObject list = call("keycloak_group_list", new JsonObject().put("search", "adm"));
        assertEquals("admins", list.getJsonArray("items").getJsonObject(0).getString("name"));

        call("keycloak_group_member_add", new JsonObject().put("groupId", "/admins/ops").put("userId", "alice"));
        JsonObject members = call("keycloak_group_members_list", new JsonObject().put("groupId", sub.getString("id")));
        assertEquals("alice", members.getJsonArray("items").getJsonObject(0).getString("username"));
        JsonObject userGroups = call("keycloak_user_groups_list", new JsonObject().put("userId", userId));
        assertEquals("/admins/ops", userGroups.getJsonArray("items").getJsonObject(0).getString("path"));

        call("keycloak_group_role_assign", new JsonObject().put("groupId", groupId).put("role", "offline_access"));
        JsonObject roles = call("keycloak_user_roles_get", new JsonObject().put("userId", "alice"));
        assertTrue(roles.getJsonArray("effectiveRealmRoles").contains("offline_access"), roles.encode());

        call("keycloak_group_member_remove", new JsonObject().put("groupId", "ops").put("userId", userId)
                .put("confirm", true));
        assertEquals(0, call("keycloak_group_members_list", new JsonObject().put("groupId", sub.getString("id")))
                .getInteger("count"));
    }

    @Test
    @Order(4)
    void roles() {
        JsonObject list = call("keycloak_role_list", new JsonObject());
        JsonArray names = new JsonArray(list.getJsonArray("items").stream()
                .map(o -> ((JsonObject) o).getString("name")).toList());
        assertTrue(names.contains("admin"), names.encode());

        call("keycloak_user_role_assign", new JsonObject().put("userId", "alice").put("role", "admin"));
        JsonObject roles = call("keycloak_user_roles_get", new JsonObject().put("userId", userId));
        assertTrue(roles.getJsonArray("realmRoles").contains("admin"));
        call("keycloak_user_role_unassign", new JsonObject().put("userId", "alice").put("role", "admin")
                .put("confirm", true));
        assertFalse(call("keycloak_user_roles_get", new JsonObject().put("userId", userId))
                .getJsonArray("realmRoles").contains("admin"));

        JsonObject clientRoles = call("keycloak_client_roles_list", new JsonObject().put("clientId", "master-realm"));
        assertEquals("master-realm", clientRoles.getString("clientId"));
        assertTrue(clientRoles.getInteger("count") > 5);

        call("keycloak_user_client_role_assign", new JsonObject().put("userId", "alice")
                .put("clientId", "master-realm").put("role", "view-users"));
        JsonObject ucr = call("keycloak_user_client_roles_get", new JsonObject().put("userId", "alice")
                .put("clientId", "master-realm"));
        assertTrue(ucr.getJsonArray("roles").contains("view-users"));
        assertTrue(ucr.getJsonArray("effectiveRoles").contains("query-users"));
        call("keycloak_user_client_role_unassign", new JsonObject().put("userId", "alice")
                .put("clientId", "master-realm").put("role", "view-users").put("confirm", true));

        JsonObject unknownRole = error("keycloak_user_role_assign", new JsonObject().put("userId", "alice")
                .put("role", "does-not-exist"));
        assertEquals("not_found", unknownRole.getString("error"));
    }

    @Test
    @Order(5)
    void deleteWithGuards() {
        JsonObject mismatch = error("keycloak_user_delete", new JsonObject().put("id", userId).put("username", "bob")
                .put("confirm", true));
        assertEquals("username_mismatch", mismatch.getString("error"));
        JsonObject needsConfirm = error("keycloak_user_delete", new JsonObject().put("id", userId)
                .put("username", "alice"));
        assertEquals("confirmation_required", needsConfirm.getString("error"));
        call("keycloak_user_delete", new JsonObject().put("id", userId).put("username", "alice").put("confirm", true));
        assertEquals("not_found", error("keycloak_user_get", new JsonObject().put("id", userId)).getString("error"));

        call("keycloak_group_delete", new JsonObject().put("id", groupId).put("confirm", true));
        assertEquals(0, call("keycloak_group_list", new JsonObject().put("search", "admins")).getInteger("count"));
    }

    @Test
    @Order(6)
    void clientsAndScopes() {
        JsonObject created = call("keycloak_client_create", new JsonObject().put("clientId", "my-app")
                .put("redirectUris", new JsonArray().add("https://app.example.com/*")).put("pkce", true)
                .put("serviceAccountsEnabled", true));
        assertEquals(false, created.getBoolean("publicClient"));

        JsonObject get = call("keycloak_client_get", new JsonObject().put("clientId", "my-app"));
        assertEquals("S256", get.getString("pkceMethod"));
        assertEquals(true, get.getBoolean("serviceAccountsEnabled"));
        assertTrue(get.getJsonArray("defaultClientScopes").contains("profile"));

        JsonObject masked = call("keycloak_client_get_secret", new JsonObject().put("clientId", "my-app"));
        assertTrue(masked.getString("secret").startsWith("****"));
        JsonObject revealed = call("keycloak_client_get_secret", new JsonObject().put("clientId", "my-app")
                .put("reveal", true));
        assertFalse(revealed.getString("secret").startsWith("****"));
        JsonObject rotated = call("keycloak_client_regenerate_secret", new JsonObject().put("clientId", "my-app")
                .put("confirm", true));
        assertFalse(rotated.getString("secret").equals(revealed.getString("secret")));

        JsonObject upd = call("keycloak_client_update", new JsonObject().put("clientId", "my-app")
                .put("webOrigins", "+").put("directAccessGrantsEnabled", "true"));
        assertTrue(upd.getJsonArray("changed").contains("webOrigins"));
        assertEquals("+", call("keycloak_client_get", new JsonObject().put("clientId", "my-app"))
                .getJsonArray("webOrigins").getString(0));

        JsonObject list = call("keycloak_client_list", new JsonObject().put("search", "my-"));
        assertEquals("my-app", list.getJsonArray("items").getJsonObject(0).getString("clientId"));

        JsonObject scopes = call("keycloak_client_scopes_list", new JsonObject());
        assertTrue(scopes.getInteger("count") > 5);
        call("keycloak_client_scope_assign", new JsonObject().put("clientId", "my-app").put("scope", "offline_access")
                .put("type", "optional"));
        JsonObject assigned = call("keycloak_client_default_scopes_get", new JsonObject().put("clientId", "my-app"));
        assertTrue(assigned.getJsonArray("optionalScopes").contains("offline_access"));
        call("keycloak_client_scope_unassign", new JsonObject().put("clientId", "my-app").put("scope", "email")
                .put("confirm", true));
        assertFalse(call("keycloak_client_default_scopes_get", new JsonObject().put("clientId", "my-app"))
                .getJsonArray("defaultScopes").contains("email"));

        JsonObject mappers = call("keycloak_client_mappers_list", new JsonObject().put("clientId", "my-app"));
        assertEquals("my-app", mappers.getString("clientId"));
        assertEquals("not_found", error("keycloak_client_get", new JsonObject().put("clientId", "nope")).getString("error"));
        assertEquals("public_client", error("keycloak_client_get_secret", new JsonObject().put("clientId", "admin-cli"))
                .getString("error"));
    }

    @Test
    @Order(7)
    void realmUpdateAndEvents() {
        JsonObject hint = call("keycloak_events_admin", new JsonObject());
        assertTrue(hint.getString("hint", "").contains("adminEventsEnabled"));
        JsonObject upd = call("keycloak_realm_update", new JsonObject().put("eventsEnabled", true)
                .put("adminEventsEnabled", true).put("organizationsEnabled", true).put("rememberMe", true)
                .put("smtpServer", new JsonObject().put("host", "mail.example.com").put("from", "kc@example.com"))
                .put("webAuthnPasswordlessPolicy", new JsonObject().put("rpEntityName", "ACME")
                        .put("userVerificationRequirement", "required").put("requireResidentKey", "Yes"))
                .put("confirm", true));
        assertTrue(upd.getJsonArray("changed").contains("smtpServer"));
        JsonObject cfg = call("keycloak_realm_get_config", new JsonObject());
        assertEquals(true, cfg.getJsonObject("login").getBoolean("rememberMe"));
        assertEquals("mail.example.com", cfg.getJsonObject("smtp").getString("host"));
        assertEquals("ACME", cfg.getJsonObject("webAuthnPasswordlessPolicy").getString("rpEntityName"));
        assertEquals(true, cfg.getBoolean("organizationsEnabled"));

        // the realm update above happened before admin events were on; this one is recorded
        call("keycloak_user_create", new JsonObject().put("username", "eve"));
        JsonObject admin = call("keycloak_events_admin", new JsonObject().put("operationType", "CREATE"));
        assertTrue(admin.getInteger("count") >= 1, admin.encode());
        assertEquals("USER", admin.getJsonArray("items").getJsonObject(0).getString("resourceType"));
        JsonObject login = call("keycloak_events_login", new JsonObject().put("type", "login_error"));
        assertEquals(0, login.getInteger("count"));
        assertNull(login.getString("hint"));
    }

    @Test
    @Order(8)
    void identityProvidersAndOrganizations() {
        call("keycloak_idp_create", new JsonObject().put("alias", "corp").put("providerId", "oidc")
                .put("displayName", "Corp SSO").put("hideOnLogin", true)
                .put("config", new JsonObject().put("clientId", "kc").put("clientSecret", "s3cret")
                        .put("authorizationUrl", "https://idp.example.com/auth")
                        .put("tokenUrl", "https://idp.example.com/token")));
        JsonObject idp = call("keycloak_idp_get", new JsonObject().put("alias", "corp"));
        assertEquals("****", idp.getJsonObject("config").getString("clientSecret"));
        assertEquals("kc", idp.getJsonObject("config").getString("clientId"));
        assertEquals(1, call("keycloak_idp_list", new JsonObject()).getInteger("count"));
        assertEquals(0, call("keycloak_idp_mappers_list", new JsonObject().put("alias", "corp")).getInteger("count"));

        JsonObject org = call("keycloak_org_create", new JsonObject().put("name", "ACME Corp").put("alias", "acme")
                .put("domains", new JsonArray().add("acme.com")));
        String orgId = org.getString("id");
        JsonObject got = call("keycloak_org_get", new JsonObject().put("organizationId", "acme"));
        assertEquals(orgId, got.getString("id"));
        assertEquals("acme.com", got.getJsonArray("domains").getString(0));
        call("keycloak_org_idp_link", new JsonObject().put("organizationId", orgId).put("idpAlias", "corp"));
        JsonObject linked = call("keycloak_org_idp_list", new JsonObject().put("organizationId", "ACME Corp"));
        assertEquals("corp", linked.getJsonArray("items").getJsonObject(0).getString("alias"));
        call("keycloak_org_idp_unlink", new JsonObject().put("organizationId", orgId).put("idpAlias", "corp")
                .put("confirm", true));
        assertEquals(0, call("keycloak_org_idp_list", new JsonObject().put("organizationId", orgId)).getInteger("count"));
        assertEquals(1, call("keycloak_org_list", new JsonObject().put("search", "acme")).getInteger("count"));
        call("keycloak_org_delete", new JsonObject().put("organizationId", orgId).put("confirm", true));
        call("keycloak_idp_delete", new JsonObject().put("alias", "corp").put("confirm", true));
        assertEquals("not_found", error("keycloak_idp_get", new JsonObject().put("alias", "corp")).getString("error"));
    }

    @Test
    @Order(9)
    void authenticationFlows() {
        JsonObject flows = call("keycloak_auth_flows_list", new JsonObject());
        JsonObject browser = flows.getJsonArray("items").stream().map(o -> (JsonObject) o)
                .filter(f -> f.getString("alias").equals("browser")).findFirst().orElseThrow();
        assertTrue(browser.getJsonArray("boundAs").contains("browserFlow"));

        JsonObject execs = call("keycloak_auth_flow_executions_list", new JsonObject().put("flowAlias", "browser"));
        assertTrue(execs.getInteger("count") > 3);
        JsonObject providers = call("keycloak_auth_authenticator_providers_list", new JsonObject());
        assertTrue(providers.getJsonArray("items").stream().anyMatch(p -> ((JsonObject) p).getString("id")
                .equals("auth-otp-form")));

        call("keycloak_auth_flow_copy", new JsonObject().put("flowAlias", "browser").put("newName", "browser-copy"));
        call("keycloak_auth_flow_create", new JsonObject().put("alias", "passkey").put("description", "passkey only"));
        JsonObject sub = call("keycloak_auth_flow_subflow_add", new JsonObject().put("parentFlowAlias", "passkey")
                .put("alias", "passkey forms").put("requirement", "REQUIRED"));
        assertNotNull(sub.getString("executionId"));
        JsonObject exec = call("keycloak_auth_flow_execution_add", new JsonObject().put("flowAlias", "passkey forms")
                .put("providerId", "webauthn-authenticator-passwordless").put("requirement", "REQUIRED"));
        assertEquals("REQUIRED", exec.getString("requirement"));
        JsonObject exec2 = call("keycloak_auth_flow_execution_add", new JsonObject().put("flowAlias", "passkey forms")
                .put("providerId", "auth-cookie"));
        call("keycloak_auth_flow_execution_raise_priority", new JsonObject().put("executionId", exec2.getString("executionId")));
        JsonObject after = call("keycloak_auth_flow_executions_list", new JsonObject().put("flowAlias", "passkey"));
        JsonObject first = after.getJsonArray("items").getJsonObject(1);
        assertEquals("auth-cookie", first.getString("providerId"));
        JsonObject updated = call("keycloak_auth_flow_execution_update", new JsonObject().put("flowAlias", "passkey")
                .put("executionId", exec2.getString("executionId")).put("requirement", "DISABLED"));
        assertEquals("DISABLED", updated.getString("requirement"));
        JsonObject bad = error("keycloak_auth_flow_execution_update", new JsonObject().put("flowAlias", "passkey")
                .put("executionId", exec2.getString("executionId")).put("requirement", "CONDITIONAL"));
        assertEquals("invalid_arguments", bad.getString("error"));

        JsonObject bound = call("keycloak_auth_flow_bind", new JsonObject().put("binding", "browserFlow")
                .put("flowAlias", "browser-copy").put("confirm", true));
        assertEquals("browser", bound.getString("previous"));
        assertEquals("browser-copy", call("keycloak_realm_get_config", new JsonObject()).getJsonObject("flows")
                .getString("browserFlow"));
        call("keycloak_auth_flow_bind", new JsonObject().put("binding", "browserFlow").put("flowAlias", "browser")
                .put("confirm", true));
        call("keycloak_auth_flow_execution_delete", new JsonObject().put("executionId", exec2.getString("executionId"))
                .put("confirm", true));
        assertEquals(2, call("keycloak_auth_flow_executions_list", new JsonObject().put("flowAlias", "passkey"))
                .getInteger("count"));

        JsonObject actions = call("keycloak_auth_required_actions_list", new JsonObject());
        assertTrue(actions.getInteger("count") > 3);
        JsonObject toggled = call("keycloak_auth_required_action_set_enabled", new JsonObject()
                .put("alias", "TERMS_AND_CONDITIONS").put("enabled", true).put("defaultAction", true));
        assertEquals(true, toggled.getBoolean("defaultAction"));
        call("keycloak_auth_required_action_set_enabled", new JsonObject().put("alias", "TERMS_AND_CONDITIONS")
                .put("enabled", false));
    }

    @Test
    @Order(10)
    void federation() {
        assertEquals(0, call("keycloak_federation_list", new JsonObject()).getInteger("count"));
        assertEquals("not_found", error("keycloak_federation_get", new JsonObject().put("id", "corp-ldap"))
                .getString("error"));
    }

    static JsonObject as(String caller, String tool, JsonObject args) {
        return McpClient.text(mcp.callTool(tool, args.put("realm", REALM),
                new JsonObject().put("kc-mcp/test-caller", caller).put("kc-mcp/test-caller-realm", REALM)));
    }

    @Test
    @Order(11)
    void policiesAgainstRealUsers() {
        // setup as the (anonymous = unrestricted) service account
        call("keycloak_user_create", new JsonObject().put("username", "p-alice"));
        call("keycloak_user_create", new JsonObject().put("username", "p-bob"));
        call("keycloak_user_create", new JsonObject().put("username", "p-carol"));
        call("keycloak_group_create", new JsonObject().put("name", "team-a"));
        call("keycloak_group_create", new JsonObject().put("name", "dev").put("parentId", "/team-a"));
        call("keycloak_group_create", new JsonObject().put("name", "team-b"));
        call("keycloak_group_member_add", new JsonObject().put("groupId", "/team-a").put("userId", "p-alice"));
        call("keycloak_user_role_assign", new JsonObject().put("userId", "p-bob").put("role", "admin"));
        // the manager role is checked against the caller's effective roles in Keycloak
        JsonObject noRole = as("p-alice", "keycloak_group_members_list", new JsonObject().put("groupId", "/team-a"));
        assertEquals("manager_role_required", noRole.getString("error"), noRole.encode());
        call("keycloak_role_list", new JsonObject()); // warm
        JsonObject mkRole = McpClient.text(mcp.callTool("execute_tool", new JsonObject()
                .put("name", "keycloak_user_role_assign").put("arguments", new JsonObject().put("realm", REALM)
                        .put("userId", "p-alice").put("role", "create-realm"))));
        assertFalse(mkRole.containsKey("error"), mkRole.encode());

        // group scope: alice is in /team-a
        JsonObject ok = as("p-alice", "keycloak_group_members_list", new JsonObject().put("groupId", "/team-a/dev"));
        assertFalse(ok.containsKey("error"), ok.encode());
        JsonObject out = as("p-alice", "keycloak_group_members_list", new JsonObject().put("groupId", "/team-b"));
        assertEquals("group_out_of_scope", out.getString("error"), out.encode());
        JsonObject sub = as("p-alice", "keycloak_group_create", new JsonObject().put("name", "ops").put("parentId", "team-a"));
        assertEquals("/team-a/ops", sub.getString("path"), sub.encode());

        // no escalation: alice holds create-realm + defaults, bob holds admin
        JsonObject grantOk = as("p-alice", "keycloak_user_role_assign", new JsonObject().put("userId", "p-carol")
                .put("role", "offline_access"));
        assertFalse(grantOk.containsKey("error"), grantOk.encode());
        JsonObject grantAdmin = as("p-alice", "keycloak_user_role_assign", new JsonObject().put("userId", "p-carol")
                .put("role", "admin"));
        assertEquals("privilege_escalation", grantAdmin.getString("error"), grantAdmin.encode());
        JsonObject touchBob = as("p-alice", "keycloak_user_set_enabled", new JsonObject().put("id", "p-bob")
                .put("enabled", false));
        assertEquals("target_outranks_caller", touchBob.getString("error"), touchBob.encode());
        JsonObject self = as("p-alice", "keycloak_user_role_assign", new JsonObject().put("userId", "p-alice")
                .put("role", "offline_access"));
        assertEquals("self_grant", self.getString("error"), self.encode());
        // bob is super (realm admin in master) and may do it
        JsonObject bobGrants = as("p-bob", "keycloak_user_role_assign", new JsonObject().put("userId", "p-carol")
                .put("role", "admin"));
        assertFalse(bobGrants.containsKey("error"), bobGrants.encode());
        // callers from another realm are refused
        JsonObject foreign = McpClient.text(mcp.callTool("keycloak_user_set_enabled", new JsonObject()
                .put("realm", REALM).put("id", "p-carol").put("enabled", true),
                new JsonObject().put("kc-mcp/test-caller", "p-alice").put("kc-mcp/test-caller-realm", "elsewhere")));
        assertEquals("caller_foreign_realm", foreign.getString("error"), foreign.encode());
    }

    @Test
    @Order(12)
    void secondSystemIsSelectable() {
        JsonArray tools = mcp.listTools();
        assertEquals(73, tools.size(), "direct mode lists every tool across pages");
        JsonObject search = tools.stream().map(t -> (JsonObject) t)
                .filter(t -> t.getString("name").equals("keycloak_user_search")).findFirst().orElseThrow();
        JsonObject props = search.getJsonObject("inputSchema").getJsonObject("properties");
        assertEquals("system", props.fieldNames().iterator().next());
        assertEquals(List.of("primary", "mirror"), props.getJsonObject("system").getJsonArray("enum").getList());

        JsonObject viaMirror = call("keycloak_user_search", new JsonObject().put("system", "mirror").put("username", "eve"));
        assertEquals("eve", viaMirror.getJsonArray("items").getJsonObject(0).getString("username"));
        JsonObject info = McpClient.text(mcp.callTool("keycloak_server_info", new JsonObject().put("system", "mirror")));
        assertTrue(info.getString("version").startsWith("26."));
        JsonObject bad = error("keycloak_user_search", new JsonObject().put("system", "nope"));
        assertEquals("invalid_arguments", bad.getString("error"));
        JsonObject notAllowed = McpClient.text(mcp.callTool("keycloak_user_search", new JsonObject()
                .put("system", "mirror").put("realm", "other")));
        assertEquals("realm_not_allowed", notAllowed.getString("error"));
    }
}
