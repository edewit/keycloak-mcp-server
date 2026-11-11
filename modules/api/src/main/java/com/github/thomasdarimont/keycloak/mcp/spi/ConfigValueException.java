package com.github.thomasdarimont.keycloak.mcp.spi;

/**
 * A setting whose value cannot be used, as a {@link ConfigProblem}: what
 * {@link ConfigProperty#parse} and the readers of {@link ProviderConfig} throw, and what
 * an extension may throw while it reads its settings to keep the code of the problem. The
 * message is the problem's English message.
 */
public class ConfigValueException extends IllegalArgumentException {

    private final transient ConfigProblem problem;

    public ConfigValueException(ConfigProblem problem) {
        super(problem.message());
        this.problem = problem;
    }

    public ConfigProblem problem() {
        return problem;
    }
}
