package com.github.thomasdarimont.keycloak.mcp.spi;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;

import com.github.thomasdarimont.keycloak.mcp.catalog.ToolLevel;

/**
 * Receives one {@link Event} per tool call, after the call finished, whatever its outcome
 * (denied, invalid arguments, Keycloak error, success). The built-in listener writes the
 * {@code com.github.thomasdarimont.keycloak.mcp.audit} log line; add your own to ship
 * audit records to a SIEM, a database or a message queue:
 * {@code @AutoService(AuditListener.class)} on the class (jars in {@code providers/} are
 * picked up), or a CDI bean.
 * <p>
 * Listeners run synchronously on the handler's virtual thread, in registration order; an
 * exception is logged and does not affect the tool result or the other listeners. Hand
 * slow deliveries off to your own executor.
 */
@FunctionalInterface
public interface AuditListener {

    void onToolCall(Event event);

    /**
     * @param at when the call finished
     * @param tool tool name, e.g. {@code keycloak_user_delete}
     * @param level read, write or destructive
     * @param system Keycloak system the call targeted, or {@code null} before it was
     * resolved
     * @param realm target realm, or {@code null} for global tools and early failures
     * @param args the arguments as received, with password / secret values replaced by
     * {@code ***}
     * @param outcome {@code ok} or the error code ({@code forbidden}, {@code not_found},
     * {@code invalid_arguments}, ...)
     * @param message error message, or {@code null} on success
     * @param via {@code direct} or {@code execute_tool}
     * @param caller who acted, with claims but without the raw token; {@link Caller#NONE}
     * on anonymous connections
     * @param clientName the MCP client's name from {@code initialize}, or {@code -}
     * @param connectionId the MCP connection id, or {@code -}
     * @param duration wall time of the call
     */
    record Event(Instant at, String tool, ToolLevel level, String system, String realm, Map<String, Object> args,
            String outcome, String message, String via, Caller caller, String clientName, String connectionId,
            Duration duration) {

        public Event {
            args = Map.copyOf(args == null ? Map.of() : args);
            caller = caller == null ? Caller.NONE : caller;
        }

        public boolean succeeded() {
            return "ok".equals(outcome);
        }
    }

}
