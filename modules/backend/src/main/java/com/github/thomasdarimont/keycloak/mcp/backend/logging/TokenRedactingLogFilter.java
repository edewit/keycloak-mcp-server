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
 * (level, category, the parts around the token such as the {@code kid}). Exception
 * messages in a logged stack trace are not rewritten. Set on the handlers with
 * {@code quarkus.log.console.filter=redact-tokens} (and {@code file}, {@code syslog}).
 */
@LoggingFilter(name = "redact-tokens")
public final class TokenRedactingLogFilter implements Filter {

    @Override
    public boolean isLoggable(LogRecord record) {
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
}
