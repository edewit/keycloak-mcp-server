package com.github.thomasdarimont.keycloak.mcp.audit;

/** The default when no {@link AuditScrubber} is registered: events pass unchanged. */
public final class NoOpAuditScrubber implements AuditScrubber {

    public static final NoOpAuditScrubber INSTANCE = new NoOpAuditScrubber();

    @Override
    public String id() {
        return "no-op-audit-scrubber";
    }

    @Override
    public String description() {
        return "audit events are recorded as built";
    }

    @Override
    public AuditEvent scrub(AuditEvent event, AuditListener target) {
        return event;
    }
}
