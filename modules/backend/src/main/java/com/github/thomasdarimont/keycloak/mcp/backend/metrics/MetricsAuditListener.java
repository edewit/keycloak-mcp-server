package com.github.thomasdarimont.keycloak.mcp.backend.metrics;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import com.github.thomasdarimont.keycloak.mcp.audit.AuditEvent;
import com.github.thomasdarimont.keycloak.mcp.audit.AuditListener;

/**
 * Turns every audited tool call into the tool and refusal metrics: the audit log is the
 * one place that sees every call with its outcome, so metrics and audit cannot drift
 * apart. Switch off alone with {@code kc-mcp.spi.metrics.enabled=false}.
 */
@ApplicationScoped
public class MetricsAuditListener implements AuditListener {

    private final KcMcpMetrics metrics;

    @Inject
    public MetricsAuditListener(KcMcpMetrics metrics) {
        this.metrics = metrics;
    }

    @Override
    public String id() {
        return "metrics";
    }

    @Override
    public String displayName() {
        return "OpenTelemetry metrics";
    }

    @Override
    public String description() {
        return "Records tool call durations and policy refusals as OpenTelemetry metrics.";
    }

    @Override
    public void onToolCall(AuditEvent event) {
        metrics.toolCall(event);
    }
}
