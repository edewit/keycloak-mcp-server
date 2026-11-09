package com.github.thomasdarimont.keycloak.mcp.backend.cli;

import java.util.LinkedHashSet;
import java.util.Set;

import com.github.thomasdarimont.keycloak.mcp.backend.keycloak.StartupChecks;
import com.github.thomasdarimont.keycloak.mcp.config.ValidationRun;

import io.quarkus.arc.Arc;
import io.quarkus.runtime.QuarkusApplication;

/** Runs once the server has booted without its listeners, for {@code validate}. */
public class ValidateApplication implements QuarkusApplication {

    static final String OFFLINE = "kcmcp.validate.offline";

    @Override
    public int run(String... args) {
        if (!Boolean.getBoolean(OFFLINE)) {
            ValidationRun
                .guard(() -> Arc.container().instance(StartupChecks.class).get().run().forEach(ValidationRun::add));
        }
        return report();
    }

    /** Prints the outcome and returns the exit code. */
    static int report() {
        Set<String> problems = new LinkedHashSet<>(ValidationRun.problems());
        problems.addAll(UnknownSettings.find());
        if (problems.isEmpty()) {
            System.out.println("The configuration is valid.");
            return 0;
        }
        System.out.println("The configuration has " + problems.size() + " problem(s):");
        problems.forEach(p -> System.out.println("  - " + p));
        return 1;
    }
}
