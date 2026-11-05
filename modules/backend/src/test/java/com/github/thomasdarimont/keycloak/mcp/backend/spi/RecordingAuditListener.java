package com.github.thomasdarimont.keycloak.mcp.backend.spi;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import com.github.thomasdarimont.keycloak.mcp.audit.AuditEvent;
import com.github.thomasdarimont.keycloak.mcp.audit.AuditListener;
import com.google.auto.service.AutoService;

/**
 * Registered through the ServiceLoader; keeps every audit event for the endpoint tests.
 */
@AutoService(AuditListener.class)
public class RecordingAuditListener implements AuditListener {

    public static final List<AuditEvent> EVENTS = new CopyOnWriteArrayList<>();

    @Override
    public void onToolCall(AuditEvent event) {
        EVENTS.add(event);
    }

}
