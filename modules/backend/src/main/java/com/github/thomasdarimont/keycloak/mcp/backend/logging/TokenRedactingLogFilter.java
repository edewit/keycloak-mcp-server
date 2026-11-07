package com.github.thomasdarimont.keycloak.mcp.backend.logging;

import java.util.Collections;
import java.util.IdentityHashMap;
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
     * Whether any message in the chain of causes and suppressed exceptions carries a
     * token. {@code seen} holds the exceptions already visited, so a cyclic chain ends.
     */
    static boolean carriesToken(Throwable t, Set<Throwable> seen) {
        if (t == null || !seen.add(t)) {
            return false;
        }
        String message = t.getMessage();
        if (message != null && !Sensitive.tokens(message).equals(message)) {
            return true;
        }
        for (Throwable s : t.getSuppressed()) {
            if (carriesToken(s, seen)) {
                return true;
            }
        }
        return carriesToken(t.getCause(), seen);
    }

    /**
     * The same exception as far as a log can tell, with every message redacted; an
     * exception met twice (a cycle) ends the copy there.
     */
    static Throwable redact(Throwable t, Set<Throwable> seen) {
        if (t == null || !seen.add(t)) {
            return null;
        }
        RedactedThrowable copy = new RedactedThrowable(t.getClass().getName(), Sensitive.tokens(t.getMessage()),
                redact(t.getCause(), seen));
        copy.setStackTrace(t.getStackTrace());
        for (Throwable s : t.getSuppressed()) {
            Throwable r = redact(s, seen);
            if (r != null) {
                copy.addSuppressed(r);
            }
        }
        return copy;
    }

    /** Prints as the original exception would, with the redacted message. */
    static final class RedactedThrowable extends Throwable {

        private static final long serialVersionUID = 1L;

        private final String className;

        RedactedThrowable(String className, String message, Throwable cause) {
            super(message, cause, true, true);
            this.className = className;
        }

        @Override
        public String toString() {
            String message = getLocalizedMessage();
            return message != null ? className + ": " + message : className;
        }
    }
}
