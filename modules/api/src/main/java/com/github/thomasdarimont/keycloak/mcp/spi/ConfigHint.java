package com.github.thomasdarimont.keycloak.mcp.spi;

import java.util.Arrays;
import java.util.List;
import java.util.Locale;

/**
 * How settings belong together, for a UI that renders an extension's settings generically
 * and for the documentation: {@link Group sections} and {@link AppliesWhen conditions}.
 * Advisory: what the server enforces of them is said per hint; every other rule between
 * settings is {@link Extension#validate}'s.
 */
public sealed interface ConfigHint permits ConfigHint.Group, ConfigHint.AppliesWhen {

    /** The settings the hint is about, by name. */
    List<String> properties();

    /**
     * Settings shown together under a label, in this order.
     *
     * @param label e.g. {@code Client authentication}
     */
    record Group(String label, List<String> properties) implements ConfigHint {

        public Group {
            if (label == null || label.isBlank()) {
                throw new IllegalArgumentException("A group needs a label");
            }
            properties = List.copyOf(properties);
        }
    }

    /**
     * A setting that only matters when another one has one of some values (or, without
     * values, is set): a UI shows it only then. The server enforces one thing: a
     * {@link ConfigProperty#required() required} setting with conditions is required only
     * while they all hold.
     *
     * @param property the setting that depends on another
     * @param on the setting it depends on: declared, or one the server handles
     * ({@code enabled})
     * @param values the values of {@code on} under which it applies, compared as the
     * declared type parses them; empty: whenever {@code on} has a value
     */
    record AppliesWhen(String property, String on, List<String> values) implements ConfigHint {

        public AppliesWhen {
            if (property == null || on == null || property.equals(on)) {
                throw new IllegalArgumentException("A condition needs a setting and another one it depends on");
            }
            values = values == null ? List.of() : List.copyOf(values);
        }

        @Override
        public List<String> properties() {
            return List.of(property);
        }

        /** Whether the condition holds for these settings, defaults included. */
        public boolean holds(ProviderConfig config) {
            ConfigProperty declared = config.declared().get(on);
            String raw = declared != null ? config.raw(declared).orElse(null) : config.get(on).orElse(null);
            if (raw == null) {
                return false;
            }
            if (values.isEmpty()) {
                return true;
            }
            String actual = canonical(declared, raw);
            return values.stream().anyMatch(v -> canonical(declared, v).equals(actual));
        }

        private static String canonical(ConfigProperty declared, String value) {
            if (declared != null) {
                try {
                    return String.valueOf(declared.parse(value)).toLowerCase(Locale.ROOT);
                }
                catch (IllegalArgumentException e) {
                    // a malformed value is reported as such; it matches nothing
                }
            }
            return value.trim().toLowerCase(Locale.ROOT);
        }

        /** {@code auth=header}, {@code keystore-file set}: for messages. */
        public String describe() {
            return values.isEmpty() ? on + " is set" : on + "=" + String.join("|", values);
        }
    }

    static Group group(String label, String... properties) {
        return new Group(label, Arrays.asList(properties));
    }

    /** {@code ConfigHint.when("header-value").is("auth", "header")} */
    static When when(String property) {
        return new When(property);
    }

    /** The first half of an {@link AppliesWhen}. */
    record When(String property) {

        public AppliesWhen is(String on, String... values) {
            return new AppliesWhen(property, on, Arrays.asList(values));
        }

        public AppliesWhen isSet(String on) {
            return new AppliesWhen(property, on, List.of());
        }
    }
}
