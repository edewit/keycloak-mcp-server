package com.github.thomasdarimont.keycloak.mcp.spi;

import java.net.URI;
import java.time.Duration;
import java.time.format.DateTimeParseException;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.github.thomasdarimont.keycloak.mcp.config.SettingValues;

import io.vertx.core.json.DecodeException;
import io.vertx.core.json.Json;

/**
 * One setting of an {@link Extension}, {@code kc-mcp.spi.<spi>.<id>.<name>}, as the
 * extension declares it in {@link Extension#configProperties()}: like Keycloak's
 * {@code ProviderConfigProperty}, the metadata the server checks the configuration
 * against at startup (unknown keys, malformed values), shows in the admin API and
 * generates documentation from. {@link ProviderConfig#readInt(ConfigProperty)} and its
 * siblings read a declared setting with its default, so name and default live in one
 * place.
 * <p>
 * Immutable; the {@code with...} methods return a copy:
 * {@snippet :
 * public static final ConfigProperty MODE = ConfigProperty.choice("mode", "keep", "drop")
 *     .withDefault("keep")
 *     .withDescription("What happens to personal data");
 * }
 *
 * @param name the key relative to the extension, kebab-case ({@code page-size})
 * @param type how the value is written and parsed
 * @param label short human readable name, the name when not given
 * @param description one or two sentences for the UI and the docs
 * @param defaultValue as it would be written in the configuration, {@code null} for none
 * @param options the allowed values of a {@link Type#CHOICE}, empty otherwise
 * @param confidential the value is masked wherever it is shown: UI, admin API, logs,
 * error messages
 * @param required startup refuses the extension when the setting is missing and has no
 * default
 */
public record ConfigProperty(String name, Type type, String label, String description, String defaultValue,
        List<String> options, boolean confidential, boolean required) {

    /** Shown instead of a {@link #confidential} value. */
    public static final String MASK = "******";

    private static final Pattern DURATION = Pattern.compile("(\\d+)(ms|s|m|h|d)?");

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
         * {@code 1d} or ISO-8601 ({@code PT30S}); {@link Duration}.
         */
        DURATION,
        /**
         * An absolute, hierarchical URL with a host ({@code file:} without);
         * {@code localhost:8080} is refused. {@link URI}.
         */
        URL,
        /** Comma separated, trimmed, empty entries dropped; {@code List<String>}. */
        LIST,
        /** One of {@link ConfigProperty#options()}, case-insensitive; the option. */
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
        label = label == null || label.isBlank() ? name : label;
        description = description == null ? "" : description;
        options = options == null ? List.of() : List.copyOf(options);
        if (type == Type.CHOICE && options.isEmpty()) {
            throw new IllegalArgumentException("Choice '" + name + "' needs options");
        }
        if (type != Type.CHOICE && !options.isEmpty()) {
            throw new IllegalArgumentException("Only a choice has options, not '" + name + "' (" + type + ")");
        }
    }

    public static ConfigProperty of(String name, Type type) {
        return new ConfigProperty(name, type, null, null, null, List.of(), false, false);
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
        return new ConfigProperty(name, Type.CHOICE, null, null, null, Arrays.asList(options), false, false);
    }

    /** The options of a choice from an enum's constants, lowercase. */
    public static <E extends Enum<E>> ConfigProperty choice(String name, Class<E> options) {
        return choice(name,
                Arrays.stream(options.getEnumConstants())
                    .map(e -> e.name().toLowerCase(Locale.ROOT))
                    .toArray(String[]::new));
    }

    public ConfigProperty withLabel(String label) {
        return new ConfigProperty(name, type, label, description, defaultValue, options, confidential, required);
    }

    public ConfigProperty withDescription(String description) {
        return new ConfigProperty(name, type, label, description, defaultValue, options, confidential, required);
    }

    /**
     * @param defaultValue as written in the configuration; checked here, so a broken
     * default fails where it is declared
     */
    public ConfigProperty withDefault(String defaultValue) {
        ConfigProperty p = new ConfigProperty(name, type, label, description, defaultValue, options, confidential,
                required);
        if (defaultValue != null) {
            p.parse(defaultValue);
        }
        return p;
    }

    /** Masks the value wherever it is shown. */
    public ConfigProperty asConfidential() {
        return new ConfigProperty(name, type, label, description, defaultValue, options, true, required);
    }

    /** Startup refuses the extension when the setting is missing and has no default. */
    public ConfigProperty asRequired() {
        return new ConfigProperty(name, type, label, description, defaultValue, options, confidential, true);
    }

    /** The value as it may be shown: {@link #MASK} when confidential. */
    public String display(String value) {
        return value == null ? null : confidential ? MASK : value;
    }

    /**
     * The value as {@link #type} describes it.
     *
     * @param value as written in the configuration
     * @throws IllegalArgumentException naming the setting and, unless confidential, the
     * value
     */
    public Object parse(String value) {
        return parse(value, "'" + name + "'");
    }

    /** {@link #parse(String)}, the setting called {@code key} in the message. */
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
            case DURATION -> parseDuration(key, v, value);
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
            case CHOICE -> options.stream()
                .filter(o -> o.equalsIgnoreCase(v))
                .findFirst()
                .orElseThrow(() -> invalid(key, value, "one of " + String.join(", ", options)));
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

    private Duration parseDuration(String key, String v, String value) {
        try {
            if (v.regionMatches(true, 0, "P", 0, 1)) {
                return Duration.parse(v.toUpperCase(Locale.ROOT));
            }
        }
        catch (DateTimeParseException e) {
            throw invalid(key, value, "a duration such as 30s, 5m or PT30S");
        }
        Matcher m = DURATION.matcher(v.toLowerCase(Locale.ROOT));
        if (!m.matches()) {
            throw invalid(key, value, "a duration such as 30s, 5m or PT30S");
        }
        long n = Long.parseLong(m.group(1));
        String unit = m.group(2) == null ? "s" : m.group(2);
        return switch (unit) {
            case "ms" -> Duration.ofMillis(n);
            case "m" -> Duration.ofMinutes(n);
            case "h" -> Duration.ofHours(n);
            case "d" -> Duration.ofDays(n);
            default -> Duration.ofSeconds(n);
        };
    }

    private IllegalArgumentException invalid(String key, String value, String expected) {
        String shown = confidential ? "" : ", not '" + value + "'";
        return new IllegalArgumentException(key + " must be " + expected + shown);
    }
}
