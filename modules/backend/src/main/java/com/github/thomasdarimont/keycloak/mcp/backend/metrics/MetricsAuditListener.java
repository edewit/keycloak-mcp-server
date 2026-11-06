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

    /**
     * Only with the OpenTelemetry SDK on ({@code quarkus.otel.sdk.disabled=false});
     * otherwise every call would be a no-op.
     */
    @Override
    public boolean isSupported(com.github.thomasdarimont.keycloak.mcp.config.McpServerConfig serverConfig,
            com.github.thomasdarimont.keycloak.mcp.spi.ProviderConfig config) {
        return !org.eclipse.microprofile.config.ConfigProvider.getConfig()
            .getOptionalValue("quarkus.otel.sdk.disabled", Boolean.class)
            .orElse(false);
    }

    @Override
    public void onToolCall(AuditEvent event) {
        metrics.toolCall(event);
    }
}
