package com.github.thomasdarimont.keycloak.mcp.backend.logging;

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

    /** Deeper cause chains are cut, as a loop would otherwise never end. */
    static final int MAX_CAUSES = 16;

    @Override
    public boolean isLoggable(LogRecord record) {
        Throwable thrown = record.getThrown();
        if (thrown != null && carriesToken(thrown, 0)) {
            record.setThrown(redact(thrown, 0));
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

    static boolean carriesToken(Throwable t, int depth) {
        if (t == null || depth > MAX_CAUSES) {
            return false;
        }
        String message = t.getMessage();
        if (message != null && !Sensitive.tokens(message).equals(message)) {
            return true;
        }
        for (Throwable s : t.getSuppressed()) {
            if (carriesToken(s, depth + 1)) {
                return true;
            }
        }
        return carriesToken(t.getCause(), depth + 1);
    }

    /** The same exception as far as a log can tell, with every message redacted. */
    static Throwable redact(Throwable t, int depth) {
        if (t == null || depth > MAX_CAUSES) {
            return null;
        }
        RedactedThrowable copy = new RedactedThrowable(t.getClass().getName(), Sensitive.tokens(t.getMessage()),
                redact(t.getCause(), depth + 1));
        copy.setStackTrace(t.getStackTrace());
        for (Throwable s : t.getSuppressed()) {
            Throwable r = redact(s, depth + 1);
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
