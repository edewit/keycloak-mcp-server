package com.github.thomasdarimont.keycloak.mcp.spi;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

/**
 * What is wrong with an extension's settings: a malformed value, a missing required one,
 * an unknown key, or a rule of the extension's own ({@link Extension#validate}). Startup
 * refuses an extension with errors and logs the warnings; the admin API returns both.
 *
 * @param severity whether the settings cannot be used ({@link Severity#ERROR}) or only
 * look wrong ({@link Severity#WARNING})
 * @param message one sentence naming the full key ({@link ProviderConfig#key}) and,
 * unless confidential, the value
 * @param properties the settings concerned, by name, for a UI to mark; several for a rule
 * between settings, none when it concerns the extension as a whole
 */
public record ConfigProblem(Severity severity, String message, List<String> properties) {

    public enum Severity {
        ERROR, WARNING
    }

    public ConfigProblem {
        if (severity == null) {
            throw new IllegalArgumentException("A config problem needs a severity");
        }
        message = message == null ? "" : message;
        properties = properties == null ? List.of() : List.copyOf(properties);
    }

    public static ConfigProblem error(String message, String... properties) {
        return new ConfigProblem(Severity.ERROR, message, Arrays.asList(properties));
    }

    public static ConfigProblem warning(String message, String... properties) {
        return new ConfigProblem(Severity.WARNING, message, Arrays.asList(properties));
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
        return severity + ": " + message;
    }
}
