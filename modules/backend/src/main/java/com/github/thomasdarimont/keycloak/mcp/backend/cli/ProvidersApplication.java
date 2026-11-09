package com.github.thomasdarimont.keycloak.mcp.backend.cli;

import java.util.List;

import com.github.thomasdarimont.keycloak.mcp.backend.spi.Extensions;
import com.github.thomasdarimont.keycloak.mcp.config.McpServerConfig;
import com.github.thomasdarimont.keycloak.mcp.config.ValidationRun;

import io.quarkus.arc.Arc;
import io.quarkus.runtime.QuarkusApplication;

/** Runs once the server has booted without its listeners, for {@code providers}. */
public class ProvidersApplication implements QuarkusApplication {

    private static final String FORMAT = "%-20s %-28s %-14s %-24s %s%n";

    @Override
    public int run(String... args) {
        List<Extensions.ProviderStatus> providers = Arc.container()
            .instance(Extensions.class)
            .get()
            .report(Arc.container().instance(McpServerConfig.class).get());
        System.out.printf(FORMAT, "SPI", "ID", "STATUS", "ORIGIN", "CLASS");
        providers.forEach(p -> System.out.printf(FORMAT, p.spi(), p.id(), p.status(), p.origin(), p.className()));
        if (!ValidationRun.problems().isEmpty()) {
            System.err
                .println("The configuration has problems, so this list may be incomplete; see the validate command.");
        }
        return 0;
    }
}
