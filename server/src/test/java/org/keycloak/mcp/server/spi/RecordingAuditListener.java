package org.keycloak.mcp.server.spi;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import org.keycloak.mcp.spi.AuditListener;

import com.google.auto.service.AutoService;

/**
 * Registered through the ServiceLoader; keeps every audit event for the endpoint tests.
 */
@AutoService(AuditListener.class)
public class RecordingAuditListener implements AuditListener {

    public static final List<Event> EVENTS = new CopyOnWriteArrayList<>();

    @Override
    public void onToolCall(Event event) {
        EVENTS.add(event);
    }

}
