package com.github.thomasdarimont.keycloak.mcp.backend.keycloak;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.junit.jupiter.api.Test;

import com.github.thomasdarimont.keycloak.mcp.config.McpServerConfig;
import com.github.thomasdarimont.keycloak.mcp.keycloak.AccessSettings;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystem;
import com.github.thomasdarimont.keycloak.mcp.keycloak.Preset;
import com.github.thomasdarimont.keycloak.mcp.keycloak.Presets;
import com.github.thomasdarimont.keycloak.mcp.keycloak.RealmSettings;

import io.smallrye.config.PropertiesConfigSource;
import io.smallrye.config.SmallRyeConfig;
import io.smallrye.config.SmallRyeConfigBuilder;
import io.vertx.core.json.JsonObject;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PresetsTest {

    static Preset preset(String name, String json) {
        // short form: every key but extends is an access check's entry
        JsonObject in = new JsonObject(json);
        JsonObject full = new JsonObject();
        JsonObject access = new JsonObject();
        in.forEach(e -> {
            if ("extends".equals(e.getKey())) {
                full.put("extends", e.getValue());
            }
            else {
                access.put(e.getKey(), e.getValue());
            }
        });
        if (!access.isEmpty()) {
            full.put("access", access);
        }
        return Preset.fromJson(name, full, "presets." + name + ".");
    }

    static Map<String, Preset> byName(Preset... presets) {
        Map<String, Preset> out = new java.util.LinkedHashMap<>();
        for (Preset p : presets) {
            out.put(p.name(), p);
        }
        return out;
    }

    static final Presets SERVER = new Presets(byName(preset("base",
            "{\"self-protection\": {\"mode\": \"reject\", \"order\": 10}, \"acme-ticket\": {\"enabled\": false}}"),
            preset("strict", "{\"extends\": \"base\", \"self-protection\": {\"mode\": \"confirm\"}}")));

    @Test
    void aPresetGoesOverItsParent() {
        AccessSettings strict = SERVER.resolve("strict", Map.of());

        assertEquals("confirm", strict.check("self-protection").settings().get("mode"), "the child's setting");
        assertEquals(Optional.of(10), strict.check("self-protection").order(), "the parent's, not repeated");
        assertEquals(Optional.of(false), strict.check("acme-ticket").enabled());
    }

    @Test
    void cyclesAreFoundAndNamed() {
        Presets loop = new Presets(byName(preset("a", "{\"extends\": \"b\"}"), preset("b", "{\"extends\": \"c\"}"),
                preset("c", "{\"extends\": \"a\"}")));
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> loop.resolve("a", Map.of()));
        assertTrue(e.getMessage().contains("a -> b -> c -> a"), e.getMessage());

        Presets self = new Presets(byName(preset("me", "{\"extends\": \"me\"}")));
        assertThrows(IllegalArgumentException.class, () -> self.validate(Map.of()));
    }

    @Test
    void chainsHaveALimit() {
        List<Preset> long_ = new ArrayList<>();
        for (int i = 0; i <= Presets.MAX_DEPTH; i++) {
            long_.add(preset("p" + i, i == Presets.MAX_DEPTH ? "{}" : "{\"extends\": \"p" + (i + 1) + "\"}"));
        }
        Presets deep = new Presets(byName(long_.toArray(Preset[]::new)));

        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> deep.resolve("p0", Map.of()));
        assertTrue(e.getMessage().contains("more than " + Presets.MAX_DEPTH), e.getMessage());
    }

    @Test
    void aSystemPresetMayExtendAServerPresetNotTheOtherWayRound() {
        Map<String, Preset> own = byName(
                preset("tenant", "{\"extends\": \"strict\", \"group-scope\": {\"enabled\": true}}"),
                preset("base", "{\"group-scope\": {\"enabled\": false}}"));

        AccessSettings tenant = SERVER.resolve("tenant", own);

        assertEquals(Optional.of(true), tenant.check("group-scope").enabled());
        assertEquals("confirm", tenant.check("self-protection").settings().get("mode"));
        assertFalse(tenant.checks().containsKey("group-scope") && tenant.check("group-scope").enabled().isEmpty());
        assertEquals(Optional.of(false), SERVER.resolve("strict", own).check("acme-ticket").enabled(),
                "strict's parent 'base' is the server's: the system's 'base' does not shadow it there");
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> SERVER.resolve("nope", own));
        assertTrue(e.getMessage().contains("known"), e.getMessage());
    }

    @Test
    void presetsThenTheSystemThenTheRealmsPresetThenTheRealm() {
        KeycloakSystem raw = KeycloakSystem.builder("prod", "https://sso")
            .preset("base")
            .access(AccessSettings.fromJson(new JsonObject("{\"self-protection\": {\"mode\": \"off-for-prod\"}}"),
                    "access."))
            .realm(new RealmSettings("acme", Optional.empty(), Optional.empty(), Optional.empty(),
                    Optional.of("strict"),
                    AccessSettings.fromJson(new JsonObject("{\"self-protection\": {\"order\": 1}}"), "access.")))
            .realm(new RealmSettings("other", Optional.of("4f2c"), Optional.empty(), Optional.empty(),
                    AccessSettings.NONE))
            .build();

        KeycloakSystem s = SERVER.apply(raw);

        assertEquals("off-for-prod", s.access("other").check("self-protection").settings().get("mode"));
        assertEquals(Optional.of(10), s.access("other").check("self-protection").order(), "from the system's preset");
        assertEquals("confirm", s.access("acme").check("self-protection").settings().get("mode"),
                "the realm's preset over the system's own");
        assertEquals(Optional.of(1), s.access("acme").check("self-protection").order(), "the realm's own last");
        assertEquals(s, SERVER.apply(s), "applying twice changes nothing");
    }

    @Test
    void anUnresolvedReferenceBlocksTheSystem() {
        KeycloakSystem raw = KeycloakSystem.builder("prod", "https://sso").preset("missing").build();
        List<String> problems = new ArrayList<>();

        KeycloakSystem s = SERVER.applyOrBlock(raw, problems::add);

        assertEquals(1, problems.size());
        assertEquals(Optional.of(true), s.access(null).check(Presets.UNRESOLVED).enabled());
    }

    @Test
    void configurationKeys() {
        SmallRyeConfig config = new SmallRyeConfigBuilder().withMapping(McpServerConfig.class)
            .withSources(new PropertiesConfigSource(Map.of("kc-mcp.presets.base.access.self-protection.mode", "reject",
                    "kc-mcp.presets.strict.extends", "base", "kc-mcp.presets.strict.access.authorization.authzen.url",
                    "https://pdp/{realm.name}", "kc-mcp.systems.prod.url", "https://sso",
                    "kc-mcp.systems.prod.client-secret", "s", "kc-mcp.systems.prod.preset", "strict",
                    "kc-mcp.systems.prod.presets.lab.access.group-scope.enabled", "false",
                    "kc-mcp.systems.prod.realms.lab1.preset", "lab"), "test", 500))
            .build();
        McpServerConfig c = config.getConfigMapping(McpServerConfig.class);

        Presets server = Presets.fromConfig(c.presets());
        KeycloakSystem prod = server.apply(KeycloakSystem.resolve("prod", c, c.systems().get("prod")));

        assertEquals("https://pdp/{realm.name}", prod.access().check("authorization").settings().get("authzen.url"));
        assertEquals("reject", prod.access().check("self-protection").settings().get("mode"));
        assertEquals(Optional.of(false), prod.access("lab1").check("group-scope").enabled());
    }

    @Test
    void systemsFileCarriesThem() {
        KeycloakSystem s = FileSystemKeycloakSystemRepository.parseSystem(new JsonObject("""
                {"name": "dyn", "url": "https://sso", "preset": "tenant",
                 "presets": {"tenant": {"extends": "strict", "access": {"group-scope": {"enabled": true}}}},
                 "realms": {"lab": {"preset": "base"}}}"""), null);

        assertEquals(Optional.of("tenant"), s.preset());
        assertEquals(Optional.of("strict"), s.presets().get("tenant").parent());
        assertEquals(Optional.of("base"), s.realms().get("lab").preset());
        assertEquals(Optional.of(true), SERVER.apply(s).access().check("group-scope").enabled());
    }

    @Test
    void aPresetHoldsSectionsNotLooseChecks() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> Preset.fromJson("x",
                new JsonObject("{\"self-protection\": {\"mode\": \"confirm\"}}"), "presets.x."));
        assertTrue(e.getMessage().contains("not a section"), e.getMessage());
        assertThrows(IllegalArgumentException.class,
                () -> Preset.fromFlat("x", Map.of("self-protection.mode", "confirm"), "kc-mcp.presets.x."));
        assertEquals("confirm",
                Preset.fromFlat("x", Map.of("access.self-protection.mode", "confirm"), "kc-mcp.presets.x.")
                    .access()
                    .check("self-protection")
                    .settings()
                    .get("mode"));
    }
}
