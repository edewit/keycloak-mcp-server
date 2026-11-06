package com.acme.keycloak.mcp;

import com.github.thomasdarimont.keycloak.mcp.audit.AuditEvent;
import com.github.thomasdarimont.keycloak.mcp.audit.AuditListener;
import com.github.thomasdarimont.keycloak.mcp.audit.AuditScrubber;
import com.google.auto.service.AutoService;

/**
 * Extension point {@link AuditScrubber}: called once per listener before it receives an
 * event. E-mail addresses leave the arguments for every sink; the console line
 * ({@code console}) additionally loses the free-text message. The database rows
 * ({@code db-audit}) and the JSON lines keep the message.
 */
@AutoService(AuditScrubber.class)
public class NoEmailScrubber implements AuditScrubber {

    @Override
    public String id() {
        return "acme-no-email";
    }

    @Override
    public AuditEvent scrub(AuditEvent event, AuditListener target) {
        AuditEvent scrubbed = event.mapArgs(key -> key.equalsIgnoreCase("email"), value -> "***");
        return "console".equals(target.id()) ? scrubbed.withMessage(null) : scrubbed;
    }
}
