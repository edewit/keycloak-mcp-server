package com.github.thomasdarimont.keycloak.mcp.backend.spi;

import java.net.URI;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;

import com.github.thomasdarimont.keycloak.mcp.audit.AuditEvent;
import com.github.thomasdarimont.keycloak.mcp.audit.AuditListener;
import com.github.thomasdarimont.keycloak.mcp.config.McpServerConfig;
import com.github.thomasdarimont.keycloak.mcp.spi.ConfigProperty;
import com.github.thomasdarimont.keycloak.mcp.spi.ProviderConfig;

import io.smallrye.config.PropertiesConfigSource;
import io.smallrye.config.SmallRyeConfigBuilder;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ConfigPropertyTest {

    enum Mode {
        KEEP, PSEUDONYMIZE, DROP
    }

    static final ConfigProperty TEXT = ConfigProperty.string("text");
    static final ConfigProperty FLAG = ConfigProperty.bool("flag").withDefault("true");
    static final ConfigProperty SIZE = ConfigProperty.integer("page-size").withDefault("20");
    static final ConfigProperty RATIO = ConfigProperty.number("ratio").withDefault("0.5");
    static final ConfigProperty TIMEOUT = ConfigProperty.duration("timeout").withDefault("30s");
    static final ConfigProperty ENDPOINT = ConfigProperty.url("pdp.url");
    static final ConfigProperty NAMES = ConfigProperty.list("names");
    static final ConfigProperty MODE = ConfigProperty.choice("mode", Mode.class).withDefault("keep");
    static final ConfigProperty EXTRA = ConfigProperty.json("extra");
    static final ConfigProperty SECRET = ConfigProperty.string("client-secret").asConfidential();
    static final ConfigProperty NEEDED = ConfigProperty.string("needed").asRequired();

    static final List<ConfigProperty> ALL = List.of(TEXT, FLAG, SIZE, RATIO, TIMEOUT, ENDPOINT, NAMES, MODE, EXTRA,
            SECRET);

    private static ProviderConfig config(Map<String, String> values, List<ConfigProperty> declared) {
        return new ProviderConfig("audit-listener", "acme", values, declared);
    }

    @Test
    void readersApplyTheDeclaredDefaults() {
        ProviderConfig c = config(Map.of(), ALL);
        assertNull(c.readString(TEXT));
        assertTrue(c.readBoolean(FLAG));
        assertEquals(20, c.readInt(SIZE));
        assertEquals(0.5, c.readNumber(RATIO));
        assertEquals(Duration.ofSeconds(30), c.readDuration(TIMEOUT));
        assertNull(c.readUrl(ENDPOINT));
        assertEquals(List.of(), c.readList(NAMES));
        assertEquals(Mode.KEEP, c.readEnum(MODE, Mode.class));
        assertNull(c.readJson(EXTRA));
        assertFalse(c.isSet(SIZE));
    }

    @Test
    void readersParseByType() {
        ProviderConfig c = config(Map.of("flag", "FALSE", "page-size", " 50 ", "ratio", "2", "timeout", "PT1M",
                "pdp.url", "https://pdp.example.com/access/v1", "names", "a, ,b", "mode", "Drop", "extra",
                "{\"a\":[1,2]}"), ALL);
        assertFalse(c.readBoolean(FLAG));
        assertEquals(50L, c.readLong(SIZE));
        assertEquals(2.0, c.readNumber(RATIO));
        assertEquals(50.0, c.readNumber(SIZE), "an INT reads as a number too");
        assertEquals(Duration.ofMinutes(1), c.readDuration(TIMEOUT));
        assertEquals(URI.create("https://pdp.example.com/access/v1"), c.readUrl(ENDPOINT));
        assertEquals(List.of("a", "b"), c.readList(NAMES));
        assertEquals("drop", c.readChoice(MODE));
        assertEquals(Mode.DROP, c.readEnum(MODE, Mode.class));
        assertEquals(new JsonObject().put("a", new JsonArray().add(1).add(2)), c.readJson(EXTRA));
    }

    @Test
    void durationsTakeUnits() {
        ProviderConfig c = config(Map.of("timeout", "90"), ALL);
        assertEquals(Duration.ofSeconds(90), c.readDuration(TIMEOUT));
        assertEquals(Duration.ofMillis(500), ConfigProperty.duration("d").parse("500ms"));
        assertEquals(Duration.ofHours(2), ConfigProperty.duration("d").parse("2h"));
        assertEquals(Duration.ofDays(1), ConfigProperty.duration("d").parse("1d"));
    }

    @Test
    void aReaderOfTheWrongTypeIsAProgrammingError() {
        ProviderConfig c = config(Map.of(), ALL);
        assertThrows(IllegalStateException.class, () -> c.readInt(TIMEOUT));
        assertThrows(IllegalStateException.class, () -> c.readInt(ConfigProperty.integer("no-default")));
    }

    @Test
    void problemsNameTheFullKeyAndHideConfidentialValues() {
        ConfigProperty pin = ConfigProperty.integer("pin").asConfidential();
        ProviderConfig c = config(
                Map.of("page-size", "many", "mode", "maybe", "pdp.url", "localhost:8080/pdp", "pin", "12x4"),
                List.of(SIZE, MODE, ENDPOINT, pin, NEEDED));
        List<String> problems = c.problems();
        assertEquals(5, problems.size(), problems.toString());
        assertTrue(problems.contains("kc-mcp.spi.audit-listener.acme.page-size must be a whole number, not 'many'"));
        assertTrue(problems
            .contains("kc-mcp.spi.audit-listener.acme.mode must be one of keep, pseudonymize, drop, not 'maybe'"));
        assertTrue(problems.contains("kc-mcp.spi.audit-listener.acme.pin must be a whole number"));
        assertTrue(problems.contains("kc-mcp.spi.audit-listener.acme.needed is required"));
        assertTrue(problems.stream().noneMatch(p -> p.contains("12x4")));
    }

    @Test
    void unknownKeysOnlyWhenDeclared() {
        Map<String, String> values = Map.of("mdoe", "drop", "enabled", "true", "required", "true", "mode", "drop");
        assertEquals(Set.of("mdoe"), config(values, ALL).unknownKeys());
        assertEquals(Set.of(), config(values, List.of()).unknownKeys());
    }

    @Test
    void displayMasksConfidentialAndUndeclaredValues() {
        ProviderConfig c = config(Map.of("mode", "drop", "client-secret", "s3cret", "other", "x", "enabled", "true"),
                ALL);
        assertEquals(Map.of("mode", "drop", "client-secret", ConfigProperty.MASK, "other", ConfigProperty.MASK,
                "enabled", "true"), c.display());
        assertFalse(c.toString().contains("s3cret"));
    }

    @Test
    void variablesMapToTheDeclaredNames() {
        Map<String, String> env = Map.of("KC_MCP_SPI_AUDIT_LISTENER_ACME_PDP_URL", "https://pdp",
                "KC_MCP_SPI_AUDIT_LISTENER_ACME_PAGE_SIZE", "5", "KC_MCP_SPI_AUDIT_LISTENER_ACME_OTHER_THING", "y");
        ProviderConfig c = ProviderConfig.forExtension("audit-listener", "acme", Map.of(), env, ALL);
        assertEquals("https://pdp", c.get("pdp.url").orElseThrow());
        assertEquals(5, c.readInt(SIZE));
        assertEquals("y", c.get("other-thing").orElseThrow(), "undeclared keys keep the kebab-case guess");
    }

    @Test
    void declarationsAreCheckedWhereTheyAreMade() {
        assertThrows(IllegalArgumentException.class, () -> ConfigProperty.integer("n").withDefault("ten"));
        assertThrows(IllegalArgumentException.class, () -> ConfigProperty.choice("c"));
        assertThrows(IllegalArgumentException.class, () -> config(Map.of(), List.of(TEXT, TEXT)));
    }

    private static McpServerConfig server(Map<String, String> values) {
        return new SmallRyeConfigBuilder().withMapping(McpServerConfig.class)
            .withSources(new PropertiesConfigSource(values, "test", 500))
            .build()
            .getConfigMapping(McpServerConfig.class);
    }

    private static final class Declaring implements AuditListener {
        boolean configured;

        @Override
        public String id() {
            return "declaring";
        }

        @Override
        public List<ConfigProperty> configProperties() {
            return List.of(MODE);
        }

        @Override
        public void configure(ProviderConfig config) {
            configured = true;
        }

        @Override
        public void onToolCall(AuditEvent event) {
        }
    }

    @Test
    void aMalformedValueStopsTheStartWhateverTheProfile() {
        Declaring e = new Declaring();
        IllegalStateException ex = assertThrows(IllegalStateException.class, () -> Extensions.usable(e, "AuditListener",
                server(Map.of("kc-mcp.spi.audit-listener.declaring.mode", "maybe"))));
        assertTrue(ex.getMessage().contains("kc-mcp.spi.audit-listener.declaring.mode must be one of"),
                ex.getMessage());
        assertFalse(e.configured);
    }

    @Test
    void unknownKeysAreOnlyLogged() {
        Declaring e = new Declaring();
        assertTrue(Extensions.usable(e, "AuditListener",
                server(Map.of("kc-mcp.spi.audit-listener.declaring.mdoe", "drop"))));
        assertTrue(e.configured);
    }
}
