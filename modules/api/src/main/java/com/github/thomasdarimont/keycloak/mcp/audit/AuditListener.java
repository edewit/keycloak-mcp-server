package com.github.thomasdarimont.keycloak.mcp.audit;

import com.github.thomasdarimont.keycloak.mcp.spi.Extension;

/**
 * Receives one {@link AuditEvent} per tool call, after the call finished, whatever its
 * outcome (denied, invalid arguments, Keycloak error, success). The built-in listener
 * writes the {@code com.github.thomasdarimont.keycloak.mcp.audit} log line; add your own
 * to ship audit records to a SIEM, a database or a message queue:
 * {@code @AutoService(AuditListener.class)} on the class (jars in {@code providers/} are
 * picked up), or a CDI bean.
 * <p>
 * Listeners run synchronously on the handler's virtual thread, in registration order; an
 * exception is logged and does not affect the tool result or the other listeners. Hand
 * slow deliveries off to your own executor.
 * <p>
 * Secrets never reach a listener (password-like arguments arrive as {@code ***}),
 * personal data does: usernames, e-mail addresses, names in arguments and messages, the
 * caller's name. Registered {@link AuditScrubber}s remove or pseudonymize it before the
 * event reaches a listener, per listener ({@link #id()} is what a scrubber targets; the
 * built-in log line is {@code log-line}), so the console can show less than the database
 * row that auditors query, or the other way round.
 */
@FunctionalInterface
public interface AuditListener extends Extension {

    void onToolCall(AuditEvent event);

}
