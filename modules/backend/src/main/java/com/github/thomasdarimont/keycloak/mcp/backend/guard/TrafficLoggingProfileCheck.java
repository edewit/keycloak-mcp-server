package com.github.thomasdarimont.keycloak.mcp.backend.guard;

import java.util.List;
import jakarta.enterprise.context.ApplicationScoped;

import com.github.thomasdarimont.keycloak.mcp.config.ProfileCheck;
import com.github.thomasdarimont.keycloak.mcp.config.ProfileCheckContext;

/**
 * The MCP library's traffic log ({@code quarkus.mcp.server.traffic-logging.enabled})
 * writes every request and response verbatim, passwords in arguments and client secrets
 * in results included; the server cannot redact it. A debugging aid for one's own
 * machine: profile {@code shared} does not start with it, {@code local} warns.
 */
@ApplicationScoped
public class TrafficLoggingProfileCheck implements ProfileCheck {

    static final String PROPERTY = "quarkus.mcp.server.traffic-logging.enabled";

    @Override
    public String id() {
        return "traffic-logging";
    }

    @Override
    public List<String> problems(ProfileCheckContext ctx) {
        return ctx.shared() && on(ctx) ? List.of(message()) : List.of();
    }

    @Override
    public List<String> warnings(ProfileCheckContext ctx) {
        return !ctx.shared() && on(ctx) ? List.of(message()) : List.of();
    }

    private static boolean on(ProfileCheckContext ctx) {
        return ctx.property(PROPERTY).map(Boolean::parseBoolean).orElse(false);
    }

    private static String message() {
        return PROPERTY + "=true writes every MCP request and response verbatim, passwords and secrets included;"
                + " turn it off outside local debugging";
    }
}
