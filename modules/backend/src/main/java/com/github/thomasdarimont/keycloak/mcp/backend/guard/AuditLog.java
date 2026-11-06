package com.github.thomasdarimont.keycloak.mcp.backend.guard;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import org.jboss.logging.Logger;

import com.github.thomasdarimont.keycloak.mcp.audit.AuditEvent;
import com.github.thomasdarimont.keycloak.mcp.audit.AuditListener;
import com.github.thomasdarimont.keycloak.mcp.audit.AuditScrubber;
import com.github.thomasdarimont.keycloak.mcp.audit.NoOpAuditScrubber;
import com.github.thomasdarimont.keycloak.mcp.catalog.Sensitive;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolResult;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolSpec;
import com.github.thomasdarimont.keycloak.mcp.spi.ExtensionRegistry;

/**
 * Builds the {@link AuditEvent} of a finished call and hands it to every listener: the
 * built-in log line first, then listeners found through the ServiceLoader and CDI.
 */
@ApplicationScoped
public class AuditLog {

    private static final Logger LOG = Logger.getLogger(AuditLog.class);

    /** Argument names whose values never reach a listener. */
    private static final List<String> SECRET_ARGS = List.of("password", "secret", "credential", "token", "key");

    /** The listener that was there from the start: the {@link ConsoleAuditListener}. */
    public static final AuditListener LOG_LINE = new ConsoleAuditListener();

    private final List<AuditListener> listeners;
    private final List<AuditScrubber> scrubbers;

    @Inject
    public AuditLog(ExtensionRegistry registry) {
        List<AuditListener> all = new ArrayList<>();
        all.add(LOG_LINE);
        all.addAll(registry.extensions(AuditListener.class));
        this.listeners = List.copyOf(all);
        for (AuditListener l : listeners) {
            if (l != LOG_LINE) {
                LOG.infof("Audit listener %s registered", l.getClass().getName());
            }
        }
        List<AuditScrubber> registered = registry.extensions(AuditScrubber.class);
        this.scrubbers = registered.isEmpty() ? List.of(NoOpAuditScrubber.INSTANCE) : List.copyOf(registered);
        for (AuditScrubber s : registered) {
            LOG.infof("Audit scrubber '%s' registered (%s)", s.id(), s.getClass().getName());
        }
    }

    /** Explicit listeners (tests, embedding); the log line is not added automatically. */
    public AuditLog(List<AuditListener> listeners) {
        this(listeners, List.of());
    }

    /** @param scrubbers run in the given order; none means events pass unchanged */
    public AuditLog(List<AuditListener> listeners, List<AuditScrubber> scrubbers) {
        this.listeners = List.copyOf(listeners);
        this.scrubbers = scrubbers.isEmpty() ? List.of(NoOpAuditScrubber.INSTANCE) : List.copyOf(scrubbers);
    }

    public List<AuditListener> listeners() {
        return listeners;
    }

    public List<AuditScrubber> scrubbers() {
        return scrubbers;
    }

    public void record(ToolSpec spec, String system, String realm, Map<String, Object> args, ToolResult result,
            InvocationContext ctx, long nanos) {
        String outcome = "ok";
        String message = null;
        if (result.isError() && result.payload() instanceof Map<?, ?> m && m.get("error") != null) {
            outcome = String.valueOf(m.get("error"));
            message = m.get("message") == null ? null : String.valueOf(m.get("message"));
        }
        else if (result.isError()) {
            outcome = "error";
            message = result.toJson();
        }
        AuditEvent event = new AuditEvent(Instant.now(), spec.name(), spec.level(), system, realm,
                Sensitive.redact(spec.inputSchema(), args), outcome, message, ctx.via(), ctx.caller().withoutToken(),
                ctx.clientName(), ctx.connectionId(), Duration.ofNanos(nanos), spec.sensitiveResult());
        for (AuditListener l : listeners) {
            try {
                AuditEvent scrubbed = event;
                for (AuditScrubber s : scrubbers) {
                    scrubbed = s.scrub(scrubbed, l);
                    if (scrubbed == null) {
                        break;
                    }
                }
                if (scrubbed != null) {
                    l.onToolCall(scrubbed);
                }
            }
            catch (RuntimeException e) {
                LOG.warnf(e, "Audit listener %s failed for %s", l.getClass().getName(), spec.name());
            }
        }
    }

    /**
     * The arguments with password-like values replaced (name hints only; see
     * {@code Sensitive}).
     */
    static Map<String, Object> redact(Map<String, Object> args) {
        return Sensitive.redact(null, args);
    }

}
