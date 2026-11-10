package com.github.thomasdarimont.keycloak.mcp.backend.authzen;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;

import com.github.thomasdarimont.keycloak.mcp.access.AccessCheck;
import com.github.thomasdarimont.keycloak.mcp.access.Caller;
import com.github.thomasdarimont.keycloak.mcp.access.GrantedRoles;
import com.github.thomasdarimont.keycloak.mcp.catalog.ApiOperation;
import com.github.thomasdarimont.keycloak.mcp.catalog.Category;
import com.github.thomasdarimont.keycloak.mcp.catalog.InputSchema;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolResult;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolSpec;

import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AuthZenRequestsTest {

    static final String R = AuthZenRequests.REALM_PREFIX;
    static final Instant NOW = Instant.parse("2026-11-10T10:00:00Z");

    static final Caller ALICE = new Caller("u-alice", "alice", "acme", true, Set.of("realm:support", "realm:admin"),
            "token",
            Map.of("iss", "https://sso/realms/acme", "azp", "claude-desktop", "act", Map.of("sub", "agent-1")));

    static ToolSpec.Builder tool(String name, Category category) {
        return ToolSpec.builder(name).title("t").description("d").category(category).handler(c -> ToolResult.ok(""));
    }

    static AccessCheck.Context ctx(ToolSpec tool, String realm, Map<String, Object> args, Caller caller) {
        return new AccessCheck.Context(tool, "prod", realm, args, GrantedRoles.UNKNOWN, caller, null);
    }

    @Test
    void userUpdateBecomesAnEvaluationOfThatUser() {
        ToolSpec spec = tool("keycloak_user_update", Category.USERS).write()
            .schema(InputSchema.builder().string("id", "id").string("email", "e"))
            .api(ApiOperation.get(R + "/users/{user-id}").path("user-id", "id"),
                    ApiOperation.put(R + "/users/{user-id}").path("user-id", "id"))
            .build();
        Map<String, Object> args = new LinkedHashMap<>(Map.of("id", "8f1c", "email", "a@b.c"));

        JsonObject req = AuthZenRequests.evaluation(ctx(spec, "acme", args, ALICE), true, NOW);

        JsonObject subject = req.getJsonObject("subject");
        assertEquals("user", subject.getString("type"));
        assertEquals("u-alice", subject.getString("id"));
        JsonObject sp = subject.getJsonObject("properties");
        assertEquals("acme", sp.getString("realm"));
        assertTrue(sp.getBoolean("delegated"));
        assertEquals(new JsonArray().add("realm:admin").add("realm:support"), sp.getJsonArray("roles"));
        assertEquals("claude-desktop", sp.getString("client_id"));

        JsonObject action = req.getJsonObject("action");
        assertEquals("keycloak_user_update", action.getString("name"));
        assertEquals("write", action.getJsonObject("properties").getString("level"));
        assertEquals("PUT /admin/realms/{realm}/users/{user-id}",
                action.getJsonObject("properties").getString("operation"), "the write, not the read before it");

        JsonObject resource = req.getJsonObject("resource");
        assertEquals("user", resource.getString("type"));
        assertEquals("8f1c", resource.getString("id"));
        assertEquals("acme", resource.getJsonObject("properties").getString("realm"));
        assertEquals("prod", resource.getJsonObject("properties").getString("system"));

        JsonObject context = req.getJsonObject("context");
        assertEquals("claude-desktop", context.getJsonObject("agent").getString("client_id"));
        assertEquals("agent-1", context.getJsonObject("agent").getJsonObject("act").getString("sub"));
        assertEquals("a@b.c", context.getJsonObject("args").getString("email"));
        assertEquals(NOW.toString(), context.getString("time"));
    }

    @Test
    void sensitiveArgumentsAreMaskedAndArgsCanBeLeftOut() {
        ToolSpec spec = tool("keycloak_user_reset_password", Category.USERS).write()
            .schema(InputSchema.builder().string("id", "id").string("password", "p").sensitive())
            .api(ApiOperation.put(R + "/users/{user-id}/reset-password").path("user-id", "id"))
            .build();
        Map<String, Object> args = Map.of("id", "8f1c", "password", "hunter22");

        JsonObject with = AuthZenRequests.evaluation(ctx(spec, "acme", args, ALICE), true, NOW);
        assertEquals("***", with.getJsonObject("context").getJsonObject("args").getString("password"));
        assertFalse(with.encode().contains("hunter22"));

        JsonObject without = AuthZenRequests.evaluation(ctx(spec, "acme", args, ALICE), false, NOW);
        assertNull(without.getJsonObject("context").getValue("args"));
        assertEquals("user", without.getJsonObject("resource").getString("type"), "the target still comes along");
    }

    @Test
    void nestedResourcesKeepTheirParentsInThePath() {
        ToolSpec spec = tool("keycloak_client_role_delete", Category.ROLES).destructive()
            .schema(InputSchema.builder().string("clientId", "c").string("role", "r"))
            .api(ApiOperation.delete(R + "/clients/{client-uuid}/roles/{role-name}")
                .path("client-uuid", "clientId")
                .path("role-name", "role"))
            .build();

        JsonObject resource = AuthZenRequests
            .resource(ctx(spec, "acme", Map.of("clientId", "billing", "role", "viewer"), ALICE));

        assertEquals("role", resource.getString("type"));
        assertEquals("viewer", resource.getString("id"));
        assertEquals(new JsonArray().add(new JsonObject().put("type", "client").put("id", "billing")),
                resource.getJsonObject("properties").getJsonArray("path"));
    }

    @Test
    void createAndListActOnTheRealmWithTheCollection() {
        ToolSpec spec = tool("keycloak_user_create", Category.USERS).write()
            .schema(InputSchema.builder().string("username", "u"))
            .api(ApiOperation.post(R + "/users"))
            .build();

        JsonObject resource = AuthZenRequests.resource(ctx(spec, "acme", Map.of("username", "bob"), ALICE));

        assertEquals("realm", resource.getString("type"));
        assertEquals("acme", resource.getString("id"));
        assertEquals("user", resource.getJsonObject("properties").getString("collection"));
    }

    @Test
    void identityProviderInstancesAndDerivedParameters() {
        ToolSpec spec = tool("keycloak_idp_get", Category.IDP).read()
            .schema(InputSchema.builder().string("alias", "a"))
            .api(ApiOperation.get(R + "/identity-provider/instances/{alias}").path("alias", "alias"))
            .build();
        assertEquals("identity-provider",
                AuthZenRequests.resource(ctx(spec, "acme", Map.of("alias", "google"), ALICE)).getString("type"));

        ToolSpec derived = tool("keycloak_x", Category.CLIENTS).read()
            .api(ApiOperation.get(R + "/clients/{client-uuid}").derivedPath("client-uuid"))
            .build();
        assertEquals("realm", AuthZenRequests.resource(ctx(derived, "acme", Map.of(), ALICE)).getString("type"),
                "a parameter the handler derives names nothing the policy could match on");
    }

    @Test
    void globalToolsActOnTheSystem() {
        ToolSpec spec = tool("keycloak_realm_list", Category.REALM).read().global().build();

        JsonObject resource = AuthZenRequests.resource(ctx(spec, null, Map.of(), ALICE));

        assertEquals("system", resource.getString("type"));
        assertEquals("prod", resource.getString("id"));
    }

    @Test
    void serviceAccountsAndAnonymousCallers() {
        Caller sa = new Caller("u-sa", "service-account-ci", "acme", false, Set.of(), null,
                Map.of("preferred_username", "service-account-ci", "client_id", "ci"));
        assertEquals("client", AuthZenRequests.subject(sa).getString("type"));
        assertEquals("ci", AuthZenRequests.subject(sa).getJsonObject("properties").getString("client_id"));

        JsonObject anonymous = AuthZenRequests.subject(Caller.NONE);
        assertEquals("anonymous", anonymous.getString("type"));
        assertEquals("anonymous", anonymous.getString("id"));
    }

    @Test
    void singular() {
        assertEquals("policy", AuthZenRequests.singular("policies"));
        assertEquals("client-scope", AuthZenRequests.singular("client-scopes"));
        assertEquals("role", AuthZenRequests.singular("roles-by-id"));
        assertEquals("brute-force", AuthZenRequests.singular("brute-force"));
    }
}
