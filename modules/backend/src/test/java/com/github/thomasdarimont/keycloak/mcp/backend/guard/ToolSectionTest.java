package com.github.thomasdarimont.keycloak.mcp.backend.guard;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.junit.jupiter.api.Test;

import com.github.thomasdarimont.keycloak.mcp.catalog.Category;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolResult;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolSpec;
import com.github.thomasdarimont.keycloak.mcp.config.McpServerConfig;
import com.github.thomasdarimont.keycloak.mcp.keycloak.AccessSettings;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystem;
import com.github.thomasdarimont.keycloak.mcp.keycloak.Preset;
import com.github.thomasdarimont.keycloak.mcp.keycloak.Presets;
import com.github.thomasdarimont.keycloak.mcp.keycloak.RealmSettings;
import com.github.thomasdarimont.keycloak.mcp.keycloak.ToolSettings;

import io.smallrye.config.PropertiesConfigSource;
import io.smallrye.config.SmallRyeConfig;
import io.smallrye.config.SmallRyeConfigBuilder;
import io.vertx.core.json.JsonObject;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The tools section: per preset, system and realm, on top of the server's restrictions.
 */
class ToolSectionTest {

    static ToolSpec tool(String name, Category category, boolean write) {
        ToolSpec.Builder b = ToolSpec.builder(name)
            .title("t")
            .description("d")
            .category(category)
            .handler(c -> ToolResult.ok(""));
        return (write ? b.write() : b.read()).build();
    }

    static final ToolSpec USER_GET = tool("keycloak_user_get", Category.USERS, false);
    static final ToolSpec USER_DELETE = tool("keycloak_user_delete", Category.USERS, true);
    static final ToolSpec CLIENT_LIST = tool("keycloak_client_list", Category.CLIENTS, false);

    static ToolSettings tools(String json) {
        return ToolSettings.fromJson(new JsonObject(json), "tools.");
    }

    static Optional<String> refusal(KeycloakSystem system, String realm, ToolSpec tool) {
        return AccessPolicy.restricted(tool, system.name(), realm, system)
            .map(r -> new JsonObject(r.toJson()).getString("error"));
    }

    @Test
    void eachRestrictionTakesToolsAway() {
        KeycloakSystem readOnly = KeycloakSystem.builder("prod", "https://sso")
            .tools(tools("{\"readOnly\": true}"))
            .build();
        assertEquals(Optional.of("read_only_mode"), refusal(readOnly, "acme", USER_DELETE));
        assertTrue(refusal(readOnly, "acme", USER_GET).isEmpty());

        KeycloakSystem denied = KeycloakSystem.builder("prod", "https://sso")
            .tools(tools("{\"denied\": [\"user_delete\"]}"))
            .build();
        assertEquals(Optional.of("tool_not_allowed"), refusal(denied, "acme", USER_DELETE), "without the prefix too");

        KeycloakSystem allowed = KeycloakSystem.builder("prod", "https://sso")
            .tools(tools("{\"allowed\": \"keycloak_user_get, client_list\"}"))
            .build();
        assertTrue(refusal(allowed, "acme", CLIENT_LIST).isEmpty());
        assertEquals(Optional.of("tool_not_allowed"), refusal(allowed, "acme", USER_DELETE));

        KeycloakSystem users = KeycloakSystem.builder("prod", "https://sso")
            .tools(tools("{\"categories\": [\"users\"]}"))
            .build();
        assertEquals(Optional.of("tool_not_allowed"), refusal(users, "acme", CLIENT_LIST));
        assertTrue(refusal(users, "acme", USER_GET).isEmpty());
    }

    @Test
    void presetThenSystemThenRealmPresetThenRealm() {
        Presets server = new Presets(Map.of("locked-down",
                Preset.fromJson("locked-down", new JsonObject("{\"tools\": {\"readOnly\": true}}"), "presets.x."),
                "no-deletes", Preset.fromJson("no-deletes",
                        new JsonObject("{\"tools\": {\"denied\": [\"user_delete\"]}}"), "presets.y.")));
        KeycloakSystem raw = KeycloakSystem.builder("prod", "https://sso")
            .preset("locked-down")
            .realm(new RealmSettings("ops", Optional.empty(), Optional.empty(), Optional.empty(),
                    Optional.of("no-deletes"), AccessSettings.NONE, tools("{\"readOnly\": false}")))
            .build();

        KeycloakSystem s = server.apply(raw);

        assertEquals(Optional.of("read_only_mode"), refusal(s, "other", USER_DELETE), "the system's preset");
        assertEquals(Optional.of("tool_not_allowed"), refusal(s, "ops", USER_DELETE),
                "ops is not read-only, but its preset denies user_delete");
        assertTrue(refusal(s, "ops", tool("keycloak_user_update", Category.USERS, true)).isEmpty(),
                "the realm's own readOnly=false over the system's preset");
    }

    @Test
    void neverWiderThanTheServer() {
        // the server's restrictions are checked first and on their own (permits); a
        // section
        // cannot open what the server closed
        AccessPolicy server = new AccessPolicy(true, List.of());
        KeycloakSystem writable = KeycloakSystem.builder("prod", "https://sso")
            .tools(tools("{\"readOnly\": false}"))
            .build();

        assertFalse(server.permits(USER_DELETE));
        assertTrue(AccessPolicy.restricted(USER_DELETE, "prod", "acme", writable).isEmpty(),
                "the section says nothing against it, the server still refuses");
    }

    @Test
    void malformedSectionsAreRefused() {
        assertThrows(IllegalArgumentException.class, () -> tools("{\"readOnly\": \"yes\"}"));
        assertThrows(IllegalArgumentException.class, () -> tools("{\"hidden\": []}"));
        assertThrows(IllegalArgumentException.class,
                () -> ToolSettings.fromFlat(Map.of("read-only", "maybe"), "kc-mcp.systems.x.tools."));
        assertThrows(IllegalArgumentException.class,
                () -> Preset.fromJson("x", new JsonObject("{\"tools\": [\"user_delete\"]}"), "presets.x."));
    }

    @Test
    void configurationKeys() {
        SmallRyeConfig config = new SmallRyeConfigBuilder().withMapping(McpServerConfig.class)
            .withSources(new PropertiesConfigSource(Map.of("kc-mcp.systems.prod.url", "https://sso",
                    "kc-mcp.systems.prod.client-secret", "s", "kc-mcp.systems.prod.tools.denied",
                    "user_delete,realm_update", "kc-mcp.systems.prod.realms.lab.tools.read-only", "true",
                    "kc-mcp.presets.viewer.tools.categories", "users,groups"), "test", 500))
            .build();
        McpServerConfig c = config.getConfigMapping(McpServerConfig.class);

        KeycloakSystem prod = KeycloakSystem.resolve("prod", c, c.systems().get("prod"));

        assertEquals(Optional.of(List.of("user_delete", "realm_update")), prod.tools(null).denied());
        assertEquals(Optional.of(true), prod.tools("lab").readOnly());
        assertEquals(Optional.of(List.of("user_delete", "realm_update")), prod.tools("lab").denied(),
                "the realm inherits what it does not set");
        assertEquals(Optional.of(List.of("users", "groups")),
                Presets.fromConfig(c.presets()).server().get("viewer").tools().categories());
    }
}
