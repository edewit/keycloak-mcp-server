package com.github.thomasdarimont.keycloak.mcp.spi;

import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * What is wrong with an extension's settings: a malformed value, a missing required one,
 * an unknown key, or a rule of the extension's own ({@link Extension#validate}). Startup
 * refuses an extension with errors and logs the warnings; the admin API returns both.
 * <p>
 * Two forms of the same problem: {@link #code()} with {@link #args()} for a UI that
 * translates it (the code is a message key, the args its named parameters), and
 * {@link #message()}, the English sentence for logs, exceptions and an untranslated UI.
 *
 * @param severity whether the settings cannot be used ({@link Severity#ERROR}) or only
 * look wrong ({@link Severity#WARNING})
 * @param code stable message key: {@code config.*} for the server's checks
 * ({@link #INVALID_VALUE}, ...), {@code <spi>.<id>.*} or a component's own prefix for an
 * extension's rules ({@code ciba.callers-required})
 * @param args named parameters of the message, by name: {@code key} (the full key) and
 * whatever the code describes; never a confidential value
 * @param message one English sentence naming the full key ({@link ProviderConfig#key})
 * and, unless confidential, the value
 * @param properties the settings concerned, by name, for a UI to mark; several for a rule
 * between settings, none when it concerns the extension as a whole
 */
public record ConfigProblem(Severity severity, String code, Map<String, String> args, String message,
        List<String> properties) {

    /**
     * A value that does not parse as its type: args {@code key}, {@code name},
     * {@code type}, {@code expected} (English), {@code value} (unless confidential), and
     * {@code options} for a choice.
     */
    public static final String INVALID_VALUE = "config.invalid-value";

    /**
     * A required setting without value: args {@code key}, {@code name}, and
     * {@code conditions} when it is required only under them.
     */
    public static final String REQUIRED = "config.required";

    /** A setting the extension does not declare: args {@code key}, {@code known}. */
    public static final String UNKNOWN_KEY = "config.unknown-key";

    /** An extension's {@link Extension#validate} that threw: args {@code error}. */
    public static final String VALIDATION_FAILED = "config.validation-failed";

    public enum Severity {
        ERROR, WARNING
    }

    public ConfigProblem {
        if (severity == null) {
            throw new IllegalArgumentException("A config problem needs a severity");
        }
        if (code == null || code.isBlank()) {
            throw new IllegalArgumentException("A config problem needs a code");
        }
        args = args == null ? Map.of() : java.util.Collections.unmodifiableMap(new LinkedHashMap<>(args));
        message = message == null ? "" : message;
        properties = properties == null ? List.of() : List.copyOf(properties);
    }

    /**
     * @param code the message key ({@code ciba.callers-required})
     * @param message the English sentence
     * @param properties the settings concerned
     */
    public static ConfigProblem error(String code, String message, String... properties) {
        return new ConfigProblem(Severity.ERROR, code, Map.of(), message, Arrays.asList(properties));
    }

    public static ConfigProblem warning(String code, String message, String... properties) {
        return new ConfigProblem(Severity.WARNING, code, Map.of(), message, Arrays.asList(properties));
    }

    /** This problem with a further named parameter; {@code null} values are left out. */
    public ConfigProblem withArg(String name, String value) {
        if (value == null) {
            return this;
        }
        Map<String, String> more = new LinkedHashMap<>(args);
        more.put(name, value);
        return new ConfigProblem(severity, code, more, message, properties);
    }

    /** This problem with further named parameters. */
    public ConfigProblem withArgs(Map<String, String> more) {
        ConfigProblem p = this;
        for (Map.Entry<String, String> e : more.entrySet()) {
            p = p.withArg(e.getKey(), e.getValue());
        }
        return p;
    }

    public boolean isError() {
        return severity == Severity.ERROR;
    }

    /** The errors among the problems. */
    public static List<ConfigProblem> errors(List<ConfigProblem> problems) {
        return problems.stream().filter(ConfigProblem::isError).toList();
    }

    /** The messages, separated by {@code ; }, for an exception or a log line. */
    public static String describe(List<ConfigProblem> problems) {
        return problems.stream().map(ConfigProblem::message).collect(Collectors.joining("; "));
    }

    @Override
    public String toString() {
        return severity + " " + code + ": " + message;
    }
}
