package com.github.thomasdarimont.keycloak.mcp.spi;

import java.net.URI;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import com.github.thomasdarimont.keycloak.mcp.config.Durations;
import com.github.thomasdarimont.keycloak.mcp.config.SettingValues;

import io.vertx.core.json.DecodeException;
import io.vertx.core.json.Json;

/**
 * One setting of an {@link Extension}, {@code kc-mcp.spi.<spi>.<id>.<name>}, as the
 * extension declares it in its {@link Extension#configSpec()}: like Keycloak's
 * {@code ProviderConfigProperty}, the metadata the server checks the configuration
 * against at startup (unknown keys, malformed values), shows in the admin API and
 * generates documentation from. {@link ProviderConfig#readInt(ConfigProperty)} and its
 * siblings read a declared setting with its default, so name and default live in one
 * place.
 * <p>
 * Immutable; the {@code with...} and {@code as...} methods return a copy:
 * {@snippet :
 * public static final ConfigProperty MODE = ConfigProperty.choice("mode", "keep", "drop").withDefault("keep");
 * }
 * Its texts are not declared here: label, description and the options' texts come from
 * the message bundles by the keys {@link ConfigMessageKeys} derives
 * ({@code <spi>.<id>.<name>.label}), resolved by {@link ConfigMessages}.
 *
 * @param name the key relative to the extension, kebab-case ({@code page-size})
 * @param type how the value is written and parsed
 * @param defaultValue as it would be written in the configuration, {@code null} for none
 * @param options the allowed values of a {@link Type#CHOICE}, empty otherwise
 * @param aliases further spellings of a choice's options, lowercase, to the option they
 * stand for ({@code true} for {@code reject}); accepted, not shown as options
 * @param confidential the value is masked wherever it is shown: UI, admin API, logs,
 * error messages
 * @param required startup refuses the extension when the setting is missing and has no
 * default
 */
public record ConfigProperty(String name, Type type, String defaultValue, List<String> options,
        Map<String, String> aliases, boolean confidential, boolean required) {

    /** Shown instead of a {@link #confidential} value. */
    public static final String MASK = "******";

    /** How a value is written and what it parses to. */
    public enum Type {
        /** Any text; {@link String}. */
        STRING,
        /** {@code true} or {@code false}, case-insensitive; {@link Boolean}. */
        BOOLEAN,
        /** A whole number; {@link Long}, read as {@code int} or {@code long}. */
        INT,
        /** A floating point number, finite; {@link Double}. */
        NUMBER,
        /**
         * {@code 30} (seconds), {@code 500ms}, {@code 30s}, {@code 5m}, {@code 2h},
         * {@code 1d} or ISO-8601 ({@code PT30S}), as {@link Durations};
         * {@link java.time.Duration}.
         */
        DURATION,
        /**
         * An absolute, hierarchical URL with a host ({@code file:} without);
         * {@code localhost:8080} is refused. {@link URI}.
         */
        URL,
        /** Comma separated, trimmed, empty entries dropped; {@code List<String>}. */
        LIST,
        /**
         * One of {@link ConfigProperty#options()} or {@link ConfigProperty#aliases()},
         * case-insensitive; the option.
         */
        CHOICE,
        /**
         * A JSON value; {@code JsonObject}, {@code JsonArray}, {@link String},
         * {@link Number}, {@link Boolean} or {@code null}.
         */
        JSON
    }

    public ConfigProperty {
        if (name == null || name.isBlank()) {
            throw new IllegalArgumentException("A config property needs a name");
        }
        if (type == null) {
            throw new IllegalArgumentException("Config property '" + name + "' needs a type");
        }
        options = options == null ? List.of() : List.copyOf(options);
        aliases = aliases == null ? Map.of() : Map.copyOf(aliases);
        if (type == Type.CHOICE && options.isEmpty()) {
            throw new IllegalArgumentException("Choice '" + name + "' needs options");
        }
        if (type != Type.CHOICE && !(options.isEmpty() && aliases.isEmpty())) {
            throw new IllegalArgumentException("Only a choice has options, not '" + name + "' (" + type + ")");
        }
        for (String target : aliases.values()) {
            if (!options.contains(target)) {
                throw new IllegalArgumentException(
                        "An alias of '" + name + "' stands for '" + target + "', which is not one of " + options);
            }
        }
    }

    public static ConfigProperty of(String name, Type type) {
        return new ConfigProperty(name, type, null, List.of(), Map.of(), false, false);
    }

    public static ConfigProperty string(String name) {
        return of(name, Type.STRING);
    }

    public static ConfigProperty bool(String name) {
        return of(name, Type.BOOLEAN);
    }

    public static ConfigProperty integer(String name) {
        return of(name, Type.INT);
    }

    public static ConfigProperty number(String name) {
        return of(name, Type.NUMBER);
    }

    public static ConfigProperty duration(String name) {
        return of(name, Type.DURATION);
    }

    public static ConfigProperty url(String name) {
        return of(name, Type.URL);
    }

    public static ConfigProperty list(String name) {
        return of(name, Type.LIST);
    }

    public static ConfigProperty json(String name) {
        return of(name, Type.JSON);
    }

    public static ConfigProperty choice(String name, String... options) {
        return new ConfigProperty(name, Type.CHOICE, null, Arrays.asList(options), Map.of(), false, false);
    }

    /**
     * The options of a choice from an enum's constants, lowercase, {@code -} for
     * {@code _} ({@code TWO_STEP} is {@code two-step}), as
     * {@link ProviderConfig#readEnum} maps them back.
     */
    public static <E extends Enum<E>> ConfigProperty choice(String name, Class<E> options) {
        return choice(name,
                Arrays.stream(options.getEnumConstants())
                    .map(e -> e.name().toLowerCase(Locale.ROOT).replace('_', '-'))
                    .toArray(String[]::new));
    }

    /**
     * @param defaultValue as written in the configuration; checked here, so a broken
     * default fails where it is declared
     */
    public ConfigProperty withDefault(String defaultValue) {
        ConfigProperty p = new ConfigProperty(name, type, defaultValue, options, aliases, confidential, required);
        if (defaultValue != null) {
            p.parse(defaultValue);
        }
        return p;
    }

    /**
     * Further spellings of the options, accepted as the option they stand for.
     *
     * @param pairs alias, option, alias, option, ...
     */
    public ConfigProperty withAliases(String... pairs) {
        if (pairs.length % 2 != 0) {
            throw new IllegalArgumentException("Aliases of '" + name + "' come in pairs: alias, option");
        }
        Map<String, String> more = new LinkedHashMap<>(aliases);
        for (int i = 0; i < pairs.length; i += 2) {
            more.put(pairs[i].toLowerCase(Locale.ROOT), pairs[i + 1]);
        }
        return new ConfigProperty(name, type, defaultValue, options, more, confidential, required);
    }

    /** Masks the value wherever it is shown. */
    public ConfigProperty asConfidential() {
        return new ConfigProperty(name, type, defaultValue, options, aliases, true, required);
    }

    /** Startup refuses the extension when the setting is missing and has no default. */
    public ConfigProperty asRequired() {
        return new ConfigProperty(name, type, defaultValue, options, aliases, confidential, true);
    }

    /** The value as it may be shown: {@link #MASK} when confidential. */
    public String display(String value) {
        return value == null ? null : confidential ? MASK : value;
    }

    /**
     * The value as {@link #type} describes it.
     *
     * @param value as written in the configuration
     * @throws ConfigValueException (an {@link IllegalArgumentException}) naming the
     * setting and, unless confidential, the value
     */
    public Object parse(String value) {
        return parse(value, null);
    }

    /**
     * {@link #parse(String)}, the setting called {@code key} in the problem.
     *
     * @param key the full key; {@code null}: the name
     * @throws ConfigValueException with a {@link ConfigProblem#INVALID_VALUE} problem
     */
    Object parse(String value, String key) {
        String v = value == null ? "" : value.trim();
        return switch (type) {
            case STRING -> value;
            case BOOLEAN -> {
                if (v.equalsIgnoreCase("true")) {
                    yield Boolean.TRUE;
                }
                if (v.equalsIgnoreCase("false")) {
                    yield Boolean.FALSE;
                }
                throw invalid(key, value, "true or false");
            }
            case INT -> {
                try {
                    yield Long.parseLong(v);
                }
                catch (NumberFormatException e) {
                    throw invalid(key, value, "a whole number");
                }
            }
            case NUMBER -> {
                try {
                    double d = Double.parseDouble(v);
                    if (Double.isNaN(d) || Double.isInfinite(d)) {
                        throw new NumberFormatException();
                    }
                    yield d;
                }
                catch (NumberFormatException e) {
                    throw invalid(key, value, "a number");
                }
            }
            case DURATION -> {
                try {
                    yield Durations.parse(v);
                }
                catch (RuntimeException e) {
                    throw invalid(key, value, "a duration such as 30s, 500ms, 5m or PT30S");
                }
            }
            case URL -> {
                try {
                    URI uri = new URI(v);
                    if (!uri.isAbsolute() || uri.isOpaque()
                            || (uri.getHost() == null && !"file".equalsIgnoreCase(uri.getScheme()))) {
                        throw new IllegalArgumentException();
                    }
                    yield uri;
                }
                catch (Exception e) {
                    throw invalid(key, value, "an absolute URL such as https://pdp.example.com/access/v1");
                }
            }
            case LIST -> List.copyOf(SettingValues.csv(v));
            case CHOICE -> {
                for (String o : options) {
                    if (o.equalsIgnoreCase(v)) {
                        yield o;
                    }
                }
                String aliased = aliases.get(v.toLowerCase(Locale.ROOT));
                if (aliased != null) {
                    yield aliased;
                }
                throw invalid(key, value, "one of " + String.join(", ", options));
            }
            case JSON -> {
                try {
                    yield Json.decodeValue(v);
                }
                catch (DecodeException e) {
                    throw invalid(key, value, "a JSON value");
                }
            }
        };
    }

    private ConfigValueException invalid(String key, String value, String expected) {
        String shown = confidential ? "" : ", not '" + value + "'";
        String where = key != null ? key : "'" + name + "'";
        ConfigProblem problem = ConfigProblem
            .error(ConfigProblem.INVALID_VALUE, where + " must be " + expected + shown, name)
            .withArg("key", key != null ? key : name)
            .withArg("name", name)
            .withArg("type", type.name())
            .withArg("expected", expected)
            .withArg("value", confidential ? null : value)
            .withArg("options", type == Type.CHOICE ? String.join(",", options) : null);
        return new ConfigValueException(problem);
    }
}
