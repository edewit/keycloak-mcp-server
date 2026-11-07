package com.github.thomasdarimont.keycloak.mcp.backend.logging;

import java.util.ArrayDeque;
import java.util.Collections;
import java.util.Deque;
import java.util.IdentityHashMap;
import java.util.Map;
import java.util.Set;
import java.util.logging.Filter;
import java.util.logging.LogRecord;

import org.jboss.logmanager.ExtLogRecord;
import org.jboss.logmanager.ExtLogRecord.FormatStyle;

import com.github.thomasdarimont.keycloak.mcp.catalog.Sensitive;

import io.quarkus.logging.LoggingFilter;

/**
 * Takes tokens out of log lines before a handler writes them. Libraries put the token
 * they failed to verify into the message: Quarkus OIDC logs jose4j's error, which prints
 * the whole JWT, signature included, and a token rejected for its audience or issuer may
 * still be valid elsewhere. Rewrites the formatted message, keeps the record otherwise
 * (level, category, the parts around the token such as the {@code kid}). A logged
 * exception whose message, or whose cause's, carries a token is replaced by a copy with
 * the redacted message and the same class name, stack frames, causes and suppressed
 * exceptions, so the printed stack trace is clean as well. Set on the handlers with
 * {@code quarkus.log.console.filter=redact-tokens} (and {@code file}, {@code syslog}).
 */
@LoggingFilter(name = "redact-tokens")
public final class TokenRedactingLogFilter implements Filter {

    @Override
    public boolean isLoggable(LogRecord record) {
        Throwable thrown = record.getThrown();
        if (thrown != null && carriesToken(thrown, Collections.newSetFromMap(new IdentityHashMap<>()))) {
            record.setThrown(redact(thrown, Collections.newSetFromMap(new IdentityHashMap<>())));
        }
        if (record instanceof ExtLogRecord ext) {
            String message = ext.getFormattedMessage();
            String redacted = Sensitive.tokens(message);
            if (redacted != null && !redacted.equals(message)) {
                ext.setMessage(redacted, FormatStyle.NO_FORMAT);
                ext.setParameters(null);
            }
        }
        else if (record.getMessage() != null
                && (record.getParameters() == null || record.getParameters().length == 0)) {
            record.setMessage(Sensitive.tokens(record.getMessage()));
        }
        return true;
    }

    /**
     * Exceptions looked at per logged throwable, causes and suppressed ones together; a
     * chain beyond that is treated as carrying a token and cut at the budget when copied,
     * so neither a cycle nor an absurd depth can exhaust the stack or leak.
     */
    static final int MAX_NODES = 1000;

    /**
     * Whether any message in the chain of causes and suppressed exceptions carries a
     * token.
     */
    static boolean carriesToken(Throwable root, Set<Throwable> seen) {
        Deque<Throwable> todo = new ArrayDeque<>();
        todo.push(root);
        while (!todo.isEmpty()) {
            Throwable t = todo.pop();
            if (t == null || !seen.add(t)) {
                continue;
            }
            if (seen.size() > MAX_NODES) {
                return true;
            }
            String message = t.getMessage();
            if (message != null && !Sensitive.tokens(message).equals(message)) {
                return true;
            }
            for (Throwable suppressed : t.getSuppressed()) {
                todo.push(suppressed);
            }
            if (t.getCause() != null) {
                todo.push(t.getCause()); // an ArrayDeque takes no null
            }
        }
        return false;
    }

    /**
     * The same exception as far as a log can tell, with every message redacted. Copies
     * are made breadth first within {@link #MAX_NODES}; an exception met twice (a cycle)
     * or beyond the budget is left out, which ends the chain there.
     */
    static Throwable redact(Throwable root, Set<Throwable> seen) {
        Map<Throwable, RedactedThrowable> copies = new IdentityHashMap<>();
        Deque<Throwable> todo = new ArrayDeque<>();
        todo.add(root);
        while (!todo.isEmpty() && copies.size() < MAX_NODES) {
            Throwable t = todo.poll();
            if (t == null || !seen.add(t)) {
                continue;
            }
            RedactedThrowable copy = new RedactedThrowable(t.getClass().getName(), Sensitive.tokens(t.getMessage()));
            copy.setStackTrace(t.getStackTrace());
            copies.put(t, copy);
            if (t.getCause() != null) {
                todo.add(t.getCause());
            }
            for (Throwable suppressed : t.getSuppressed()) {
                todo.add(suppressed);
            }
        }
        for (Map.Entry<Throwable, RedactedThrowable> e : copies.entrySet()) {
            Throwable original = e.getKey();
            RedactedThrowable copy = e.getValue();
            RedactedThrowable cause = copies.get(original.getCause());
            if (cause != null && cause != copy) {
                copy.initCause(cause);
            }
            for (Throwable suppressed : original.getSuppressed()) {
                RedactedThrowable s = copies.get(suppressed);
                if (s != null && s != copy) {
                    copy.addSuppressed(s);
                }
            }
        }
        return copies.get(root);
    }

    /** Prints as the original exception would, with the redacted message. */
    static final class RedactedThrowable extends Throwable {

        private static final long serialVersionUID = 1L;

        private final String className;

        RedactedThrowable(String className, String message) {
            super(message);
            this.className = className;
        }

        @Override
        public String toString() {
            String message = getLocalizedMessage();
            return message != null ? className + ": " + message : className;
        }
    }
}
