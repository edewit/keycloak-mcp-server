package com.github.thomasdarimont.keycloak.mcp.backend.metrics;

import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import com.github.thomasdarimont.keycloak.mcp.access.Caller;
import com.github.thomasdarimont.keycloak.mcp.audit.AuditEvent;
import com.github.thomasdarimont.keycloak.mcp.backend.Fixtures;
import com.github.thomasdarimont.keycloak.mcp.backend.guard.ConfirmerChain;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolLevel;
import com.github.thomasdarimont.keycloak.mcp.confirm.ConfirmationRequest;
import com.github.thomasdarimont.keycloak.mcp.confirm.Confirmer;
import com.github.thomasdarimont.keycloak.mcp.confirm.Decision;

import io.opentelemetry.api.common.Attributes;
import io.opentelemetry.sdk.metrics.SdkMeterProvider;
import io.opentelemetry.sdk.metrics.data.MetricData;
import io.opentelemetry.sdk.testing.exporter.InMemoryMetricReader;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class KcMcpMetricsTest {

    private final InMemoryMetricReader reader = InMemoryMetricReader.create();
    private final SdkMeterProvider provider = SdkMeterProvider.builder().registerMetricReader(reader).build();

    @AfterEach
    void close() {
        provider.close();
    }

    private KcMcpMetrics metrics(boolean realm) {
        return new KcMcpMetrics(provider.get(KcMcpMetrics.SCOPE), realm);
    }

    private static AuditEvent event(String tool, ToolLevel level, String outcome, String realm) {
        Caller alice = Caller.of("sub-1", "alice", "demo", Set.of("realm:admin"));
        return AuditEvent.builder()
            .at(Instant.now())
            .tool(tool)
            .level(level)
            .system("prod")
            .realm(realm)
            .args(Map.of("username", "dave", "password", "***"))
            .outcome(outcome)
            .via("execute_tool")
            .caller(alice)
            .clientName("LM Studio")
            .connectionId("conn-1")
            .duration(Duration.ofMillis(42))
            .build();
    }

    private MetricData metric(Collection<MetricData> all, String name) {
        return all.stream()
            .filter(m -> m.getName().equals(name))
            .findFirst()
            .orElseThrow(() -> new AssertionError(name + " not in " + all.stream().map(MetricData::getName).toList()));
    }

    @Test
    void toolCallsAreHistogrammedWithBoundedAttributesOnly() {
        KcMcpMetrics m = metrics(false);
        m.toolCall(event("keycloak_user_search", ToolLevel.READ, "ok", "demo"));
        m.toolCall(event("keycloak_user_search", ToolLevel.READ, "ok", "other"));
        m.toolCall(event("keycloak_user_delete", ToolLevel.DESTRUCTIVE, "not_found", "demo"));

        Collection<MetricData> all = reader.collectAllMetrics();
        MetricData calls = metric(all, "kc_mcp.tool.call.duration");
        assertEquals("s", calls.getUnit());
        var points = calls.getHistogramData().getPoints();
        assertEquals(2, points.size(), "realm off: both searches fall into one series");
        var search = points.stream()
            .filter(p -> "keycloak_user_search".equals(p.getAttributes().get(KcMcpMetrics.TOOL)))
            .findFirst()
            .orElseThrow();
        assertEquals(2, search.getCount());
        assertEquals(0.084, search.getSum(), 1e-6);
        Attributes a = search.getAttributes();
        assertEquals("read", a.get(KcMcpMetrics.LEVEL));
        assertEquals("ok", a.get(KcMcpMetrics.OUTCOME));
        assertEquals("execute_tool", a.get(KcMcpMetrics.VIA));
        assertEquals("prod", a.get(KcMcpMetrics.SYSTEM));
        assertEquals(5, a.size(), "tool, level, outcome, via, system and nothing about the caller: " + a);
        assertFalse(a.asMap().values().stream().anyMatch(v -> v.toString().contains("alice")));
        assertTrue(all.stream().noneMatch(d -> d.getName().equals("kc_mcp.policy.refusals")),
                "not_found is not a refusal");
    }

    @Test
    void realmIsAnOptInAttribute() {
        KcMcpMetrics m = metrics(true);
        m.toolCall(event("keycloak_user_search", ToolLevel.READ, "ok", "demo"));
        m.toolCall(event("keycloak_user_search", ToolLevel.READ, "ok", "other"));
        m.toolCall(event("keycloak_server_info", ToolLevel.READ, "ok", null));
        var points = metric(reader.collectAllMetrics(), "kc_mcp.tool.call.duration").getHistogramData().getPoints();
        assertEquals(3, points.size());
        assertTrue(points.stream().anyMatch(p -> "-".equals(p.getAttributes().get(KcMcpMetrics.REALM))),
                "global tools: -");
    }

    @Test
    void refusalsAreCountedByReason() {
        KcMcpMetrics m = metrics(false);
        m.toolCall(event("keycloak_user_role_assign", ToolLevel.WRITE, "privilege_escalation", "demo"));
        m.toolCall(event("keycloak_user_role_assign", ToolLevel.WRITE, "privilege_escalation", "demo"));
        m.toolCall(event("keycloak_user_delete", ToolLevel.DESTRUCTIVE, "forbidden", "demo"));
        var points = metric(reader.collectAllMetrics(), "kc_mcp.policy.refusals").getLongSumData().getPoints();
        assertEquals(2, points.size());
        var escalation = points.stream()
            .filter(p -> "privilege_escalation".equals(p.getAttributes().get(KcMcpMetrics.REASON)))
            .findFirst()
            .orElseThrow();
        assertEquals(2, escalation.getValue());
        assertEquals("write", escalation.getAttributes().get(KcMcpMetrics.LEVEL));
    }

    @Test
    void oddValuesAreCutToShortTokens() {
        assertEquals("-", KcMcpMetrics.token(null));
        assertEquals("-", KcMcpMetrics.token(" "));
        assertEquals("acme_error_with_spaces", KcMcpMetrics.token("acme error with spaces"));
        assertEquals(64, KcMcpMetrics.token("x".repeat(500)).length());
    }

    @Test
    void cibaCountersAndPendingGauge() {
        KcMcpMetrics m = metrics(false);
        m.cibaFiled("prod");
        m.cibaFiled("prod");
        m.cibaDecision("approved", "prod", Duration.ofSeconds(4));
        m.cibaDecision("rejected", "prod", Duration.ofSeconds(2));
        m.pendingApprovals(() -> 3);
        m.pendingApprovals(() -> 99); // registered once
        Collection<MetricData> all = reader.collectAllMetrics();
        assertEquals(2, metric(all, "kc_mcp.ciba.requests").getLongSumData().getPoints().iterator().next().getValue());
        var decisions = metric(all, "kc_mcp.ciba.decisions").getLongSumData().getPoints();
        assertEquals(Set.of("approved", "rejected"),
                decisions.stream().map(p -> p.getAttributes().get(KcMcpMetrics.OUTCOME)).collect(Collectors.toSet()));
        assertEquals(2, metric(all, "kc_mcp.ciba.decision.duration").getHistogramData().getPoints().size());
        assertEquals(3, metric(all, "kc_mcp.ciba.pending").getLongGaugeData().getPoints().iterator().next().getValue());
    }

    @Test
    void confirmationDecisionsNameTheConfirmer() {
        KcMcpMetrics m = metrics(false);
        Confirmer ticket = new Confirmer() {
            @Override
            public Decision confirm(ConfirmationRequest r) {
                return Boolean.TRUE.equals(r.args().get("ticket")) ? Decision.confirmed() : Decision.abstain();
            }

            @Override
            public String id() {
                return "acme-ticket";
            }
        };
        Confirmer boom = new Confirmer() {
            @Override
            public Decision confirm(ConfirmationRequest r) {
                if (Boolean.TRUE.equals(r.args().get("boom"))) {
                    throw new IllegalStateException("down");
                }
                return Decision.abstain();
            }

            @Override
            public String id() {
                return "flaky";
            }

            @Override
            public int order() {
                return -1;
            }
        };
        ConfirmerChain chain = new ConfirmerChain(List.of(boom, ticket)).metrics(m);
        var spec = Fixtures.specs()
            .stream()
            .filter(s -> s.name().equals("keycloak_user_delete"))
            .findFirst()
            .orElseThrow();
        chain.confirm(new ConfirmationRequest(spec, null, "demo", Map.of("ticket", true), false, Caller.NONE, null));
        chain.confirm(new ConfirmationRequest(spec, null, "demo", Map.of(), false, Caller.NONE, null));
        chain.confirm(new ConfirmationRequest(spec, null, "demo", Map.of("boom", true), false, Caller.NONE, null));
        var points = metric(reader.collectAllMetrics(), "kc_mcp.confirmation.decisions").getLongSumData().getPoints();
        assertEquals(Set.of("acme-ticket/confirmed", "none/confirmation_required", "flaky/failed"), points.stream()
            .map(p -> p.getAttributes().get(KcMcpMetrics.CONFIRMER) + "/" + p.getAttributes().get(KcMcpMetrics.OUTCOME))
            .collect(Collectors.toSet()));
    }
}
