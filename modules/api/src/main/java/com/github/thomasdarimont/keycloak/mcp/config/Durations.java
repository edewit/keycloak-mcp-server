package com.github.thomasdarimont.keycloak.mcp.config;

import java.time.Duration;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.eclipse.microprofile.config.spi.Converter;

/**
 * Durations as people write them in configuration: {@code 10s}, {@code 500ms},
 * {@code 2m}, {@code 1h}, {@code 1d}, ISO-8601 ({@code PT10S}), or a bare number of
 * seconds. The same rules as Quarkus' own durations, without depending on Quarkus.
 */
public final class Durations {

    private static final Pattern SIMPLE = Pattern.compile("(\\d+)(ms|s|m|h|d)?");

    private Durations() {
    }

    /** @throws IllegalArgumentException for anything else */
    public static Duration parse(String value) {
        String v = value == null ? "" : value.trim().toLowerCase(Locale.ROOT);
        if (v.isEmpty()) {
            throw new IllegalArgumentException("empty duration");
        }
        if (v.startsWith("p")) {
            return Duration.parse(v.toUpperCase(Locale.ROOT));
        }
        Matcher m = SIMPLE.matcher(v);
        if (!m.matches()) {
            throw new IllegalArgumentException("'" + value + "' is not a duration (e.g. 10s, 500ms, 2m, PT1M)");
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

    public static class DurationConverter implements Converter<Duration> {
        @Override
        public Duration convert(String value) {
            return parse(value);
        }
    }
}
