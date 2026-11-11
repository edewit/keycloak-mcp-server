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
import com.github.thomasdarimont.keycloak.mcp.spi.ConfigHint;
import com.github.thomasdarimont.keycloak.mcp.spi.ConfigMessageKeys;
import com.github.thomasdarimont.keycloak.mcp.spi.ConfigProblem;
import com.github.thomasdarimont.keycloak.mcp.spi.ConfigProperty;
import com.github.thomasdarimont.keycloak.mcp.spi.ConfigSpec;
import com.github.thomasdarimont.keycloak.mcp.spi.ConfigValueException;
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
        List<String> problems = c.problems().stream().map(ConfigProblem::message).toList();
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
        ProviderConfig c = ProviderConfig.forExtension("audit-listener", "acme", Map.of(), env, ConfigSpec.of(ALL));
        assertEquals("https://pdp", c.get("pdp.url").orElseThrow());
        assertEquals(5, c.readInt(SIZE));
        assertEquals("y", c.get("other-thing").orElseThrow(), "undeclared keys keep the kebab-case guess");
    }

    @Test
    void declarationsAreCheckedWhereTheyAreMade() {
        assertThrows(IllegalArgumentException.class, () -> ConfigProperty.integer("n").withDefault("ten"));
        assertThrows(IllegalArgumentException.class, () -> ConfigProperty.choice("c"));
        assertThrows(IllegalArgumentException.class, () -> config(Map.of(), List.of(TEXT, TEXT)));
        assertThrows(IllegalArgumentException.class,
                () -> ConfigSpec.of(TEXT).withHints(ConfigHint.when(TEXT.name()).is("nope", "x")),
                "a condition on an undeclared setting");
        assertThrows(IllegalArgumentException.class, () -> ConfigSpec.of(TEXT).withHints(ConfigHint.group("g", "nope")),
                "a group of undeclared settings");
        ConfigSpec.of(TEXT).withHints(ConfigHint.when(TEXT.name()).is("enabled", "true"));
    }

    private static McpServerConfig server(Map<String, String> values) {
        return new SmallRyeConfigBuilder().withMapping(McpServerConfig.class)
            .withSources(new PropertiesConfigSource(values, "test", 500))
            .build()
            .getConfigMapping(McpServerConfig.class);
    }

    private static final class Declaring implements AuditListener {
        boolean configured;
        List<ConfigProblem> rules = List.of();

        @Override
        public String id() {
            return "declaring";
        }

        @Override
        public ConfigSpec configSpec() {
            return ConfigSpec.of(MODE);
        }

        @Override
        public List<ConfigProblem> validate(ProviderConfig config) {
            return rules;
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

    @Test
    void aliasesStandForTheirOption() {
        ConfigProperty mode = ConfigProperty.choice("mode", "off", "reject", "confirm")
            .withAliases("true", "reject", "false", "off");
        assertEquals("reject", mode.parse("TRUE"));
        assertEquals("off", mode.parse("false"));
        assertEquals("confirm", mode.parse("confirm"));
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> mode.parse("maybe"));
        assertEquals("'mode' must be one of off, reject, confirm, not 'maybe'", e.getMessage(),
                "aliases are accepted, not offered");
        assertThrows(IllegalArgumentException.class, () -> mode.withAliases("yes", "accept"));
    }

    @Test
    void enumOptionsAreKebabCase() {
        enum Flow {
            TWO_STEP, BLOCKING
        }
        ConfigProperty flow = ConfigProperty.choice("flow", Flow.class);
        assertEquals(List.of("two-step", "blocking"), flow.options());
        assertEquals(Flow.TWO_STEP, config(Map.of("flow", "two-step"), List.of(flow)).readEnum(flow, Flow.class));
    }

    @Test
    void messagesNameWhereTheSettingsAreWritten() {
        ProviderConfig c = config(Map.of("page-size", "x"), ALL).describedAs("kc-mcp.systems.prod.acme.");
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> c.readInt(SIZE));
        assertEquals("kc-mcp.systems.prod.acme.page-size must be a whole number, not 'x'", e.getMessage());
    }

    @Test
    void theExtensionsOwnRulesRunAfterTheSpecsChecks() {
        Declaring e = new Declaring();
        e.rules = List.of(ConfigProblem.error("acme.rule-broken", "acme rule broken", "mode"));
        IllegalStateException ex = assertThrows(IllegalStateException.class,
                () -> Extensions.usable(e, "AuditListener", server(Map.of())));
        assertTrue(ex.getMessage().contains("acme rule broken"), ex.getMessage());

        e.rules = List.of(ConfigProblem.warning("acme.rule-odd", "acme rule looks odd", "mode"));
        assertTrue(Extensions.usable(e, "AuditListener", server(Map.of())), "a warning is only logged");

        ProviderConfig malformed = new ProviderConfig("audit-listener", "declaring", Map.of("mode", "maybe"),
                e.configSpec());
        e.rules = null; // would throw if called
        assertEquals(1, malformed.problems(e).size(), "rules are not asked while the values do not parse");
    }

    @Test
    void aRequiredSettingWithConditionsIsRequiredWhileTheyHold() {
        ConfigProperty auth = ConfigProperty.choice("auth", "none", "header").withDefault("none");
        ConfigProperty value = ConfigProperty.string("header-value").asRequired();
        ConfigSpec spec = ConfigSpec.of(auth, value).withHints(ConfigHint.when(value.name()).is(auth.name(), "header"));

        assertTrue(new ProviderConfig("acme", Map.of(), spec).problems().isEmpty(), "auth=none by default");
        List<ConfigProblem> problems = new ProviderConfig("acme", Map.of("auth", "HEADER"), spec).problems();
        assertEquals(List.of("kc-mcp.spi.acme.header-value is required when auth=header"),
                problems.stream().map(ConfigProblem::message).toList());
        assertEquals(List.of("header-value"), problems.getFirst().properties());
        assertTrue(
                new ProviderConfig("acme", Map.of("auth", "header", "header-value", "x"), spec).problems().isEmpty());

        ConfigSpec onEnabled = ConfigSpec.of(value).withHints(ConfigHint.when(value.name()).is("enabled", "true"));
        assertTrue(new ProviderConfig("acme", Map.of(), onEnabled).problems().isEmpty());
        assertEquals(1, new ProviderConfig("acme", Map.of("enabled", "TRUE"), onEnabled).problems().size(),
                "a server's own key can be the condition");
        ConfigSpec onSet = ConfigSpec.of(TEXT, value).withHints(ConfigHint.when(value.name()).isSet(TEXT.name()));
        assertEquals(1, new ProviderConfig("acme", Map.of("text", "x"), onSet).problems().size());
    }

    @Test
    void specsCombineTheFirstDeclarationWinning() {
        ConfigProperty secret = ConfigProperty.string("client-secret").asConfidential();
        ConfigSpec own = ConfigSpec.of(TEXT, ConfigProperty.string("client-secret"))
            .withHints(ConfigHint.group("own", "text"));
        ConfigSpec other = ConfigSpec.of(secret, FLAG).withHints(ConfigHint.when(FLAG.name()).isSet(secret.name()));
        ConfigSpec both = own.plus(other);
        assertEquals(List.of("text", "client-secret", "flag"), List.copyOf(both.names()));
        assertFalse(both.property("client-secret").orElseThrow().confidential(), "declared here first");
        assertEquals(2, both.hints().size());
        assertEquals(both, both.plus(other), "hints come along once");
    }

    @Test
    void problemsCarryACodeAndNamedArgumentsForTranslation() {
        ConfigProperty pin = ConfigProperty.integer("pin").asConfidential();
        ConfigProperty value = ConfigProperty.string("header-value").asRequired();
        ConfigSpec spec = ConfigSpec.of(MODE, pin, value)
            .withHints(ConfigHint.when(value.name()).is(MODE.name(), "drop"));
        List<ConfigProblem> problems = new ProviderConfig("audit-listener", "acme",
                Map.of("mode", "drop", "pin", "12x4", "mdoe", "x"), spec)
            .problems();

        ConfigProblem pinProblem = problems.stream()
            .filter(p -> p.properties().contains("pin"))
            .findFirst()
            .orElseThrow();
        assertEquals(ConfigProblem.INVALID_VALUE, pinProblem.code());
        assertEquals("kc-mcp.spi.audit-listener.acme.pin", pinProblem.args().get("key"));
        assertEquals("INT", pinProblem.args().get("type"));
        assertFalse(pinProblem.args().containsKey("value"), "a confidential value is no argument either");

        ConfigProblem required = problems.stream()
            .filter(p -> p.code().equals(ConfigProblem.REQUIRED))
            .findFirst()
            .orElseThrow();
        assertEquals("mode=drop", required.args().get("conditions"));

        ConfigProblem unknown = problems.stream()
            .filter(p -> p.code().equals(ConfigProblem.UNKNOWN_KEY))
            .findFirst()
            .orElseThrow();
        assertEquals("mode,pin,header-value", unknown.args().get("known"));

        ConfigValueException e = assertThrows(ConfigValueException.class, () -> MODE.parse("maybe"));
        assertEquals("keep,pseudonymize,drop", e.problem().args().get("options"));
        assertEquals("maybe", e.problem().args().get("value"));
    }

    @Test
    void messageKeysFollowFromTheSpec() {
        String prefix = ConfigMessageKeys.prefix("audit-scrubber", "pii");
        ConfigHint.Group group = ConfigHint.group("scrubbing", "mode");
        assertEquals("audit-scrubber.pii.mode.label", ConfigMessageKeys.label(prefix, MODE));
        assertEquals("audit-scrubber.pii.mode.description", ConfigMessageKeys.description(prefix, MODE));
        assertEquals("audit-scrubber.pii.mode.option.drop", ConfigMessageKeys.option(prefix, MODE, "drop"));
        assertEquals("audit-scrubber.pii.group.scrubbing.label", ConfigMessageKeys.label(prefix, group));
        assertEquals("audit-scrubber.pii.group.scrubbing.description", ConfigMessageKeys.description(prefix, group));
        assertEquals("tools.acme-tickets.", ConfigMessageKeys.prefix("tools", "acmeTickets"), "the id kebab-cased");
        assertThrows(IllegalArgumentException.class, () -> ConfigHint.group("Scrubbing", "mode"),
                "a group id is kebab-case");
        assertThrows(IllegalArgumentException.class,
                () -> ConfigSpec.of(MODE).withHints(ConfigHint.group("g", "mode"), ConfigHint.group("g", "mode")),
                "group ids are unique");
    }
}
