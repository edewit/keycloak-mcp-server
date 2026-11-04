package org.keycloak.mcp.server.guard;

import java.util.function.Function;

import org.keycloak.mcp.catalog.ToolException;
import org.keycloak.mcp.catalog.ToolResult;

/**
 * Maps exceptions thrown by handlers to structured error results. The Keycloak adapter
 * registers a mapper for JAX-RS {@code WebApplicationException}s so this package does not
 * depend on the REST client.
 */
public final class ErrorMapper {

    private static volatile Function<Throwable, ToolResult> extra = t -> null;

    private ErrorMapper() {
    }

    public static void register(Function<Throwable, ToolResult> mapper) {
        Function<Throwable, ToolResult> previous = extra;
        extra = t -> {
            ToolResult r = mapper.apply(t);
            return r != null ? r : previous.apply(t);
        };
    }

    public static ToolResult map(Throwable t) {
        ToolResult mapped = extra.apply(t);
        if (mapped != null) {
            return mapped;
        }
        if (t instanceof IllegalArgumentException) {
            return ToolResult.error("invalid_arguments", t.getMessage());
        }
        if (t instanceof ToolException te) {
            return ToolResult.error(te.code(), te.getMessage());
        }
        String msg = t.getMessage() == null ? t.getClass().getSimpleName() : t.getMessage();
        return ToolResult.error("tool_failed", msg);
    }
}
