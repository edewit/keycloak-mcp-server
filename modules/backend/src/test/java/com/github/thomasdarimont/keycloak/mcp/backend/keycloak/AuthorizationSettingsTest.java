package com.github.thomasdarimont.keycloak.mcp.backend.keycloak;

import java.util.Map;
import java.util.Optional;

import org.junit.jupiter.api.Test;

import com.github.thomasdarimont.keycloak.mcp.config.McpServerConfig;
import com.github.thomasdarimont.keycloak.mcp.keycloak.AuthorizationSettings;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystem;
import com.github.thomasdarimont.keycloak.mcp.keycloak.RealmSettings;

import io.smallrye.config.PropertiesConfigSource;
import io.smallrye.config.SmallRyeConfig;
import io.smallrye.config.SmallRyeConfigBuilder;
import io.vertx.core.json.JsonObject;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AuthorizationSettingsTest {

    static final String JSON = """
            {"enabled": true,
             "authzen": {"url": "https://pdp/e", "clientAuth": "private_key_jwt", "clientSecret": "s3cret",
                         "headerValue": "vault:pdp-key", "sendArgs": false},
             "acmeOpa": {"endpoint": "https://opa/v1", "apiKey": "opa-k3y"}}""";

    static AuthorizationSettings parse(String json) {
        return AuthorizationSettings.fromJson(new JsonObject(json));
    }

    @Test
    void enginesAreNestedBlocks() {
        AuthorizationSettings a = parse(JSON);

        assertEquals(Optional.of(true), a.enabled());
        assertEquals("private_key_jwt", a.engine("authzen").get("client-auth"));
        assertEquals("false", a.engine("authzen").get("send-args"));
        assertEquals("https://opa/v1", a.engine("acme-opa").get("endpoint"), "engine ids in kebab-case");
        assertEquals(Map.of(), a.engine("other"));

        assertEquals(a, AuthorizationSettings.fromJson(a.toJson(false)), "round trip");
        assertEquals(false, a.toJson(false).getJsonObject("authzen").getValue("sendArgs"), "booleans stay booleans");
    }

    @Test
    void representationsMaskSecretsOfEveryEngineButNotReferences() {
        JsonObject masked = parse(JSON).toJson(true);

        assertEquals("***", masked.getJsonObject("authzen").getString("clientSecret"));
        assertEquals("vault:pdp-key", masked.getJsonObject("authzen").getString("headerValue"));
        assertEquals("***", masked.getJsonObject("acme-opa").getString("apiKey"), "by name, for any engine");
        assertFalse(parse(JSON).toString().contains("s3cret"));
    }

    @Test
    void whichEnginesEvaluate() {
        assertTrue(parse("{\"enabled\": true}").usesEngine("authzen"), "naming none: every engine");
        assertTrue(parse(JSON).usesEngine("authzen"));
        assertFalse(parse("{\"acme-opa\": {}}").usesEngine("authzen"), "naming others: not this one");

        assertTrue(parse("{}").evaluatedBy("authzen", true), "the engine's default");
        assertFalse(parse("{}").evaluatedBy("authzen", false));
        assertFalse(parse("{\"enabled\": false}").evaluatedBy("authzen", true));
    }

    @Test
    void aRealmOverlaysItsSystem() {
        AuthorizationSettings system = parse(JSON);

        AuthorizationSettings sandbox = system.overlay(parse("{\"enabled\": false}"));
        assertEquals(Optional.of(false), sandbox.enabled(), "the realm's switch wins");
        assertEquals(system.engines(), sandbox.engines());

        AuthorizationSettings acme = system.overlay(parse("{\"authzen\": {\"url\": \"https://pdp/acme\"}}"));
        assertEquals(Optional.of(true), acme.enabled(), "no switch of its own: the system's");
        assertEquals("https://pdp/acme", acme.engine("authzen").get("url"), "the realm's setting wins");
        assertEquals("private_key_jwt", acme.engine("authzen").get("client-auth"), "the others stay");

        KeycloakSystem s = KeycloakSystem.builder("prod", "https://sso")
            .authorization(system)
            .realm(new RealmSettings("sandbox", parse("{\"enabled\": false}")))
            .build();
        assertFalse(s.authorization("sandbox").evaluates(true));
        assertTrue(s.authorization("other").evaluates(false));
        assertTrue(s.authorization(null).evaluates(false), "a global tool follows the system");
    }

    @Test
    void malformedBlocksAreRefused() {
        assertThrows(IllegalArgumentException.class, () -> parse("{\"enabled\": \"yes\"}"));
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> parse("{\"url\": \"https://x\"}"));
        assertTrue(e.getMessage().contains("engine"), e.getMessage());
        assertThrows(IllegalArgumentException.class, () -> parse("{\"authzen\": {\"url\": [\"a\"]}}"));
        assertThrows(IllegalArgumentException.class, () -> AuthorizationSettings.fromFlat(Map.of("url", "https://x")));
        assertThrows(IllegalArgumentException.class,
                () -> RealmSettings.fromJson("acme", new JsonObject("{\"realms\": {}}")));
    }

    @Test
    void realmSettingsCarryLabelsAndKeycloaksId() {
        RealmSettings r = RealmSettings.fromJson("acme", new JsonObject("""
                {"realmId": "4f2c", "displayName": "ACME", "description": "ACME's customers",
                 "access": {"authorization": {"enabled": false}, "group-scope": {"order": 3}}}"""));

        assertEquals(Optional.of("4f2c"), r.realmId());
        assertEquals(Optional.of("ACME"), r.displayName());
        assertEquals(r, RealmSettings.fromJson("acme", r.toJson(false)), "round trip");
        assertFalse(r.isEmpty());
        assertTrue(new RealmSettings("acme", (AuthorizationSettings) null).isEmpty());
        assertTrue(KeycloakSystem.builder("s", "https://sso")
            .realm(new RealmSettings("x", (AuthorizationSettings) null))
            .build()
            .realms()
            .isEmpty(), "a realm without settings is not kept");
    }

    @Test
    void configurationKeysIncludingRealmNamesWithDots() {
        SmallRyeConfig config = new SmallRyeConfigBuilder().withMapping(McpServerConfig.class)
            .withSources(new PropertiesConfigSource(Map.of("kc-mcp.systems.prod.url", "https://sso.example",
                    "kc-mcp.systems.prod.client-secret", "s", "kc-mcp.systems.prod.access.authorization.enabled",
                    "true", "kc-mcp.systems.prod.access.authorization.authzen.client-auth", "private_key_jwt",
                    "kc-mcp.systems.prod.realms.sandbox.access.authorization.enabled", "false",
                    "kc-mcp.systems.prod.realms.sandbox.display-name", "Sandbox",
                    "kc-mcp.systems.prod.realms.\"acme.eu\".access.authorization.authzen.url", "https://pdp/eu"),
                    "test", 500))
            .build();
        McpServerConfig c = config.getConfigMapping(McpServerConfig.class);

        KeycloakSystem prod = KeycloakSystem.resolve("prod", c, c.systems().get("prod"));

        assertEquals(Optional.of(true), prod.authorization().enabled());
        assertEquals("private_key_jwt", prod.authorization().engine("authzen").get("client-auth"));
        assertEquals(Optional.of("Sandbox"), prod.realms().get("sandbox").displayName());
        assertFalse(prod.authorization("sandbox").evaluates(true));
        assertEquals("https://pdp/eu", prod.authorization("acme.eu").engine("authzen").get("url"));
    }

    @Test
    void systemsFileAndBuilderCarryTheBlocks() {
        KeycloakSystem s = FileSystemKeycloakSystemRepository.parseSystem(new JsonObject().put("name", "dyn")
            .put("url", "https://sso")
            .put("access", new JsonObject().put("authorization", new JsonObject(JSON)))
            .put("realms", new JsonObject("{\"sandbox\": {\"displayName\": \"Sandbox\","
                    + " \"access\": {\"authorization\": {\"enabled\": false}}}}")),
                null);
        assertEquals("https://pdp/e", s.authorization().engine("authzen").get("url"));
        assertEquals(Optional.of("Sandbox"), s.realms().get("sandbox").displayName());
        assertEquals(s.authorization(), s.toBuilder().build().authorization());
        assertEquals(s.realms(), s.toBuilder().build().realms());
        assertThrows(IllegalArgumentException.class, () -> FileSystemKeycloakSystemRepository
            .parseSystem(new JsonObject().put("name", "x").put("url", "https://sso").put("access", "on"), null));
    }
}
