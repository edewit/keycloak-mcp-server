package com.github.thomasdarimont.keycloak.mcp.backend.guard;

import org.jboss.logging.Logger;

import com.github.thomasdarimont.keycloak.mcp.audit.AuditEvent;
import com.github.thomasdarimont.keycloak.mcp.audit.AuditListener;

/**
 * The built-in audit listener: one {@code com.github.thomasdarimont.keycloak.mcp.audit}
 * log line per tool call. Always registered first; an {@code AuditScrubber} addresses it
 * as {@code console} to keep personal data out of the log while other sinks keep it.
 */
public final class ConsoleAuditListener implements AuditListener {

    public static final String ID = "console";

    private static final Logger AUDIT = Logger.getLogger("com.github.thomasdarimont.keycloak.mcp.audit");

    @Override
    public String id() {
        return ID;
    }

    @Override
    public String displayName() {
        return "Console audit log";
    }

    @Override
    public String description() {
        return "one " + AUDIT.getName() + " log line per call";
    }

    @Override
    public void onToolCall(AuditEvent e) {
        AUDIT.infof("tool=%s level=%s system=%s realm=%s outcome=%s via=%s caller=%s%s client=%s conn=%s ms=%d",
                e.tool(), e.level(), e.system() == null ? "-" : e.system(), e.realm() == null ? "-" : e.realm(),
                e.outcome(), e.via(),
                e.caller().isAnonymous() ? "-" : e.caller().name() + "(" + e.caller().subject() + ")",
                e.caller().delegated() ? " delegated" : "", e.clientName(), e.connectionId(), e.duration().toMillis());
    }
}
