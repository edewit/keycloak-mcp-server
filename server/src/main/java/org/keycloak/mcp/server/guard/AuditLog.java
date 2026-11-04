package org.keycloak.mcp.server.guard;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;

import org.jboss.logging.Logger;
import org.keycloak.mcp.catalog.ToolResult;
import org.keycloak.mcp.catalog.ToolSpec;
import org.keycloak.mcp.server.spi.ToolProviderRegistry;
import org.keycloak.mcp.spi.AuditListener;

/**
 * Builds the {@link AuditListener.Event} of a finished call and hands it to every
 * listener: the built-in log line first, then listeners found through the ServiceLoader
 * and CDI.
 */
@ApplicationScoped
public class AuditLog {

    private static final Logger LOG = Logger.getLogger(AuditLog.class);
    private static final Logger AUDIT = Logger.getLogger("org.keycloak.mcp.audit");

    /** Argument names whose values never reach a listener. */
    private static final List<String> SECRET_ARGS = List.of("password", "secret", "credential", "token", "key");

    /** The listener that was there from the start: one log line per call. */
    public static final AuditListener LOG_LINE = e -> AUDIT.infof(
            "tool=%s level=%s system=%s realm=%s outcome=%s via=%s caller=%s%s client=%s conn=%s ms=%d", e.tool(),
            e.level(), e.system() == null ? "-" : e.system(), e.realm() == null ? "-" : e.realm(), e.outcome(), e.via(),
            e.caller().isAnonymous() ? "-" : e.caller().name() + "(" + e.caller().subject() + ")",
            e.caller().delegated() ? " delegated" : "", e.clientName(), e.connectionId(), e.duration().toMillis());

    private final List<AuditListener> listeners;

    @Inject
    public AuditLog(Instance<AuditListener> cdiListeners) {
        List<AuditListener> all = new ArrayList<>();
        all.add(LOG_LINE);
        all.addAll(ToolProviderRegistry.discover(AuditListener.class));
        for (AuditListener l : cdiListeners) {
            all.add(l);
        }
        this.listeners = List.copyOf(all);
        for (AuditListener l : listeners) {
            if (l != LOG_LINE) {
                LOG.infof("Audit listener %s registered", l.getClass().getName());
            }
        }
    }

    /** Explicit listeners (tests, embedding); the log line is not added automatically. */
    public AuditLog(List<AuditListener> listeners) {
        this.listeners = List.copyOf(listeners);
    }

    public List<AuditListener> listeners() {
        return listeners;
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
        AuditListener.Event event = new AuditListener.Event(Instant.now(), spec.name(), spec.level(), system, realm,
                redact(args), outcome, message, ctx.via(), ctx.caller().withoutToken(), ctx.clientName(),
                ctx.connectionId(), Duration.ofNanos(nanos));
        for (AuditListener l : listeners) {
            try {
                l.onToolCall(event);
            }
            catch (RuntimeException e) {
                LOG.warnf(e, "Audit listener %s failed for %s", l.getClass().getName(), spec.name());
            }
        }
    }

    /**
     * Replaces values of password-like arguments (any nesting level is not needed:
     * schemas are flat).
     */
    static Map<String, Object> redact(Map<String, Object> args) {
        if (args == null || args.isEmpty()) {
            return Map.of();
        }
        Map<String, Object> out = new LinkedHashMap<>();
        args.forEach((k, v) -> {
            String key = k.toLowerCase(Locale.ROOT);
            boolean secret = v != null && SECRET_ARGS.stream().anyMatch(key::contains);
            out.put(k, secret ? "***" : v);
        });
        return out;
    }

}
