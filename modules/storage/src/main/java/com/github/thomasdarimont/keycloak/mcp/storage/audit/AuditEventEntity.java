package com.github.thomasdarimont.keycloak.mcp.storage.audit;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import io.quarkus.hibernate.orm.panache.PanacheEntityBase;

/**
 * A row of {@code kc_mcp_audit_event}: one finished tool call, whatever its outcome
 * ({@code AuditEvent}).
 */
@Entity
@Table(name = "kc_mcp_audit_event")
public class AuditEventEntity extends PanacheEntityBase {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id")
    public Long id;

    /** Epoch milliseconds. */
    @Column(name = "occurred_at", nullable = false)
    public long occurredAt;

    @Column(name = "tool", nullable = false, length = 255)
    public String tool;

    /** {@code READ}, {@code WRITE} or {@code DESTRUCTIVE}. */
    @Column(name = "level", nullable = false, length = 16)
    public String level;

    @Column(name = "system_alias", length = 255)
    public String system;

    @Column(name = "realm", length = 255)
    public String realm;

    /** The arguments as a JSON object, secrets already replaced by {@code ***}. */
    @JdbcTypeCode(SqlTypes.LONG32VARCHAR)
    @Column(name = "args")
    public String args;

    /** {@code ok} or the error code. */
    @Column(name = "outcome", nullable = false, length = 64)
    public String outcome;

    @JdbcTypeCode(SqlTypes.LONG32VARCHAR)

    @Column(name = "message")
    public String message;

    /** {@code direct} or {@code execute_tool}. */
    @Column(name = "via", length = 32)
    public String via;

    @Column(name = "caller_subject", length = 255)
    public String callerSubject;

    @Column(name = "caller_name", length = 255)
    public String callerName;

    @Column(name = "caller_realm", length = 255)
    public String callerRealm;

    @Column(name = "delegated", nullable = false)
    public boolean delegated;

    @Column(name = "client_name", length = 255)
    public String clientName;

    @Column(name = "connection_id", length = 255)
    public String connectionId;

    @Column(name = "duration_ms", nullable = false)
    public long durationMs;

    /** The OpenTelemetry trace the call ran in, 32 hex digits; null without tracing. */
    @Column(name = "trace_id", length = 32)
    public String traceId;

    @Column(name = "span_id", length = 16)
    public String spanId;
}
