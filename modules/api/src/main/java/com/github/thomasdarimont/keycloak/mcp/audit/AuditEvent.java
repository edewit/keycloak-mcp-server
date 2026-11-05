package com.github.thomasdarimont.keycloak.mcp.audit;

import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Predicate;
import java.util.function.UnaryOperator;

import com.github.thomasdarimont.keycloak.mcp.access.Caller;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolLevel;

/**
 * One finished tool call as the {@link AuditListener}s see it.
 *
 * @param at when the call finished
 * @param tool tool name, e.g. {@code keycloak_user_delete}
 * @param level read, write or destructive
 * @param system Keycloak system the call targeted, or {@code null} before it was resolved
 * @param realm target realm, or {@code null} for global tools and early failures
 * @param args the arguments as received, with password / secret values replaced by
 * {@code ***}
 * @param outcome {@code ok} or the error code ({@code forbidden}, {@code not_found},
 * {@code invalid_arguments}, ...)
 * @param message error message, or {@code null} on success
 * @param via {@code direct} or {@code execute_tool}
 * @param caller who acted, with claims but without the raw token; {@link Caller#NONE} on
 * anonymous connections
 * @param clientName the MCP client's name from {@code initialize}, or {@code -}
 * @param connectionId the MCP connection id, or {@code -}
 * @param duration wall time of the call
 */
public record AuditEvent(Instant at, String tool, ToolLevel level, String system, String realm,
        Map<String, Object> args, String outcome, String message, String via, Caller caller, String clientName,
        String connectionId, Duration duration) {

    public AuditEvent {
        args = Map.copyOf(args == null ? Map.of() : args);
        caller = caller == null ? Caller.NONE : caller;
    }

    public boolean succeeded() {
        return "ok".equals(outcome);
    }

    /** The same event with other arguments. */
    public AuditEvent withArgs(Map<String, Object> newArgs) {
        return new AuditEvent(at, tool, level, system, realm, newArgs, outcome, message, via, caller, clientName,
                connectionId, duration);
    }

    /**
     * The same event with the values of the matching argument names replaced by what the
     * function returns for them ({@code mapArgs(k -> k.equals("email"), v -> "***")}); a
     * {@code null} result removes the argument.
     */
    public AuditEvent mapArgs(Predicate<String> argName, UnaryOperator<Object> value) {
        Map<String, Object> out = new LinkedHashMap<>();
        args.forEach((k, v) -> {
            Object mapped = argName.test(k) ? value.apply(v) : v;
            if (mapped != null) {
                out.put(k, mapped);
            }
        });
        return withArgs(out);
    }

    /** The same event with another message ({@code null} for none). */
    public AuditEvent withMessage(String newMessage) {
        return new AuditEvent(at, tool, level, system, realm, args, outcome, newMessage, via, caller, clientName,
                connectionId, duration);
    }

    /** The same event with another caller ({@code null} for {@link Caller#NONE}). */
    public AuditEvent withCaller(Caller newCaller) {
        return new AuditEvent(at, tool, level, system, realm, args, outcome, message, via, newCaller, clientName,
                connectionId, duration);
    }
}
