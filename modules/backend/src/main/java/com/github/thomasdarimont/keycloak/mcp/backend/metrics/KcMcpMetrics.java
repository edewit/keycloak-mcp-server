package com.github.thomasdarimont.keycloak.mcp.backend.metrics;

import java.time.Duration;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.LongSupplier;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import com.github.thomasdarimont.keycloak.mcp.audit.AuditEvent;
import com.github.thomasdarimont.keycloak.mcp.config.McpServerConfig;

import io.opentelemetry.api.OpenTelemetry;
import io.opentelemetry.api.common.AttributeKey;
import io.opentelemetry.api.common.Attributes;
import io.opentelemetry.api.common.AttributesBuilder;
import io.opentelemetry.api.metrics.DoubleHistogram;
import io.opentelemetry.api.metrics.LongCounter;
import io.opentelemetry.api.metrics.Meter;

/**
 * The server's own OpenTelemetry metrics, next to the HTTP and JVM metrics Quarkus
 * reports:
 * <ul>
 * <li>{@code kc_mcp.tool.call.duration} (histogram, s; its count is the number of calls):
 * {@code tool}, {@code level}, {@code outcome} ({@code ok} or the error code),
 * {@code via}, {@code system}, and {@code realm} when
 * {@code kc-mcp.metrics.include-realm=true}</li>
 * <li>{@code kc_mcp.policy.refusals} (counter): {@code reason} (the refusal code),
 * {@code tool}, {@code level}, {@code system}</li>
 * <li>{@code kc_mcp.confirmation.decisions} (counter): {@code confirmer} (its id, or
 * {@code none} when every confirmer abstained), {@code outcome}, {@code tool}</li>
 * <li>{@code kc_mcp.ciba.requests} (counter): CIBA requests filed, by {@code system}</li>
 * <li>{@code kc_mcp.ciba.decisions} (counter) and {@code kc_mcp.ciba.decision.duration}
 * (histogram, s, from filing to the answer): {@code outcome} = approved, declined,
 * expired, timeout or rejected (the ID token was invalid or named someone else: alert on
 * it), {@code system}</li>
 * <li>{@code kc_mcp.ciba.pending} (gauge): approvals waiting for a device</li>
 * </ul>
 * No user, subject, argument or client-supplied value becomes an attribute: the values
 * are bounded by the catalog, the configuration and the server's own codes, and anything
 * else is cut to a short token. Who did what is the audit log's job. With the SDK off
 * ({@code quarkus.otel.sdk.disabled=true}, the default) every instrument is a no-op.
 */
@ApplicationScoped
public class KcMcpMetrics {

    public static final String SCOPE = "keycloak-mcp-server";

    static final AttributeKey<String> TOOL = AttributeKey.stringKey("tool");
    static final AttributeKey<String> LEVEL = AttributeKey.stringKey("level");
    static final AttributeKey<String> OUTCOME = AttributeKey.stringKey("outcome");
    static final AttributeKey<String> VIA = AttributeKey.stringKey("via");
    static final AttributeKey<String> SYSTEM = AttributeKey.stringKey("system");
    static final AttributeKey<String> REALM = AttributeKey.stringKey("realm");
    static final AttributeKey<String> REASON = AttributeKey.stringKey("reason");
    static final AttributeKey<String> CONFIRMER = AttributeKey.stringKey("confirmer");

    /**
     * Outcomes that mean the server refused on purpose (policy, access, configuration),
     * not that something broke.
     */
    static final Set<String> REFUSALS = Set.of("forbidden", "privilege_escalation", "target_outranks_caller",
            "self_grant", "group_out_of_scope", "manager_role_required", "caller_unknown", "caller_foreign_realm",
            "caller_required", "realm_not_allowed", "read_only_mode", "tool_not_allowed", "entry_mismatch",
            "delegation_not_allowed", "delegation_required", "delegation_failed", "access_check_failed",
            "system_required", "realm_required", "unsupported");

    /**
     * Histogram buckets in seconds: tool calls take milliseconds, CIBA decisions up to
     * minutes.
     */
    static final List<Double> CALL_BUCKETS = List.of(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
            30.0, 60.0, 120.0);
    static final List<Double> DECISION_BUCKETS = List.of(1.0, 2.0, 5.0, 10.0, 20.0, 30.0, 60.0, 120.0, 300.0);

    private final Meter meter;
    private final boolean includeRealm;
    private final DoubleHistogram toolDuration;
    private final LongCounter refusals;
    private final LongCounter confirmations;
    private final LongCounter cibaRequests;
    private final LongCounter cibaDecisions;
    private final DoubleHistogram cibaDecisionDuration;
    private final AtomicBoolean pendingGauge = new AtomicBoolean();

    @Inject
    public KcMcpMetrics(OpenTelemetry otel, McpServerConfig config) {
        this(otel.getMeter(SCOPE), config.metrics().includeRealm());
    }

    public KcMcpMetrics(Meter meter, boolean includeRealm) {
        this.meter = meter;
        this.includeRealm = includeRealm;
        this.toolDuration = meter.histogramBuilder("kc_mcp.tool.call.duration")
            .setDescription("Duration of tool calls; the count is the number of calls")
            .setUnit("s")
            .setExplicitBucketBoundariesAdvice(CALL_BUCKETS)
            .build();
        this.refusals = meter.counterBuilder("kc_mcp.policy.refusals")
            .setDescription("Tool calls the server refused on purpose: roles, policies, realm limits, read-only mode")
            .build();
        this.confirmations = meter.counterBuilder("kc_mcp.confirmation.decisions")
            .setDescription("Confirmation decisions of destructive tools, by the confirmer that decided")
            .build();
        this.cibaRequests = meter.counterBuilder("kc_mcp.ciba.requests")
            .setDescription("CIBA authentication requests filed with the caller's device")
            .build();
        this.cibaDecisions = meter.counterBuilder("kc_mcp.ciba.decisions")
            .setDescription("Answers to CIBA requests; outcome=rejected means the approval named someone else")
            .build();
        this.cibaDecisionDuration = meter.histogramBuilder("kc_mcp.ciba.decision.duration")
            .setDescription("Time from filing a CIBA request to the device's answer")
            .setUnit("s")
            .setExplicitBucketBoundariesAdvice(DECISION_BUCKETS)
            .build();
    }

    /** Metrics that record nothing (tests, embedding). */
    public static KcMcpMetrics noop() {
        return new KcMcpMetrics(OpenTelemetry.noop().getMeter(SCOPE), false);
    }

    /** One finished tool call, as the audit log sees it. */
    public void toolCall(AuditEvent e) {
        String outcome = token(e.outcome());
        AttributesBuilder a = Attributes.builder()
            .put(TOOL, token(e.tool()))
            .put(LEVEL, e.level() == null ? "-" : e.level().name().toLowerCase())
            .put(OUTCOME, outcome)
            .put(VIA, token(e.via()))
            .put(SYSTEM, token(e.system()));
        if (includeRealm) {
            a.put(REALM, token(e.realm()));
        }
        toolDuration.record(e.duration() == null ? 0 : e.duration().toNanos() / 1e9, a.build());
        if (REFUSALS.contains(outcome)) {
            refusals.add(1,
                    Attributes.builder()
                        .put(REASON, outcome)
                        .put(TOOL, token(e.tool()))
                        .put(LEVEL, e.level() == null ? "-" : e.level().name().toLowerCase())
                        .put(SYSTEM, token(e.system()))
                        .build());
        }
    }

    /**
     * A confirmation decision; {@code confirmer} is {@code none} when every one
     * abstained.
     */
    public void confirmation(String confirmer, String outcome, String tool) {
        confirmations.add(1, Attributes.of(CONFIRMER, token(confirmer), OUTCOME, token(outcome), TOOL, token(tool)));
    }

    public void cibaFiled(String system) {
        cibaRequests.add(1, Attributes.of(SYSTEM, token(system)));
    }

    /** @param outcome approved, declined, expired, timeout or rejected */
    public void cibaDecision(String outcome, String system, Duration sinceFiled) {
        Attributes a = Attributes.of(OUTCOME, token(outcome), SYSTEM, token(system));
        cibaDecisions.add(1, a);
        if (sinceFiled != null && !sinceFiled.isNegative()) {
            cibaDecisionDuration.record(sinceFiled.toMillis() / 1000.0, a);
        }
    }

    /** Registers the gauge of waiting approvals once; a negative reading is skipped. */
    public void pendingApprovals(LongSupplier count) {
        // lock-free: the first caller registers, later ones return (no synchronized,
        // virtual thread friendly)
        if (!pendingGauge.compareAndSet(false, true)) {
            return;
        }
        meter.gaugeBuilder("kc_mcp.ciba.pending")
            .ofLongs()
            .setDescription("CIBA approvals waiting for the caller's device")
            .buildWithCallback(m -> {
                long n;
                try {
                    n = count.getAsLong();
                }
                catch (RuntimeException e) {
                    return;
                }
                if (n >= 0) {
                    m.record(n);
                }
            });
    }

    /**
     * A bounded attribute value: {@code -} for none, otherwise at most 64 characters of
     * letters, digits and {@code ._-:}, so an odd value from an extension cannot blow up
     * the series or carry text.
     */
    static String token(String v) {
        if (v == null || v.isBlank()) {
            return "-";
        }
        String clean = v.replaceAll("[^A-Za-z0-9._:-]", "_");
        return clean.length() <= 64 ? clean : clean.substring(0, 64);
    }
}
