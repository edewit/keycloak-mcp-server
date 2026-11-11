package com.github.thomasdarimont.keycloak.mcp.storage.audit;

import java.util.List;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.transaction.Transactional;

import org.hibernate.Session;

import com.github.thomasdarimont.keycloak.mcp.audit.AuditEvent;
import com.github.thomasdarimont.keycloak.mcp.audit.AuditListener;
import com.github.thomasdarimont.keycloak.mcp.spi.ConfigProperty;
import com.github.thomasdarimont.keycloak.mcp.spi.ConfigSpec;
import com.github.thomasdarimont.keycloak.mcp.storage.StorageEnabledInterceptorFactory;

import io.quarkus.arc.lookup.LookupIfProperty;
import io.quarkus.panache.common.Sort;
import io.vertx.core.json.JsonObject;

/**
 * Writes one {@code kc_mcp_audit_event} row per finished tool call, synchronously on the
 * handler's thread so the record exists before the result leaves the server; a database
 * failure is logged by the server and does not change the tool result. Arguments arrive
 * redacted; personal data is the {@link PiiAuditScrubber}'s business. Rows are kept until
 * {@link AuditRetention} removes them
 * ({@code kc-mcp.spi.audit-listener.db.retention-days}, off by default). Switch it off
 * alone with {@code kc-mcp.spi.audit-listener.db.enabled=false}.
 */
@ApplicationScoped
@LookupIfProperty(name = StorageEnabledInterceptorFactory.ENABLED, stringValue = "true")
public class DatabaseAuditListener implements AuditListener {

    public static final String ID = "db";

    /** Read by {@link AuditRetention}. */
    public static final ConfigProperty RETENTION_DAYS = ConfigProperty.integer("retention-days").withDefault("0");

    public static final ConfigSpec CONFIG_SPEC = ConfigSpec.of(RETENTION_DAYS);

    @Override
    public String id() {
        return ID;
    }

    @Override
    public ConfigSpec configSpec() {
        return CONFIG_SPEC;
    }

    @Override
    public String displayName() {
        return "Database audit log";
    }

    @Override
    public String description() {
        return "one kc_mcp_audit_event row per tool call";
    }

    /**
     * The row as a plain insert instead of {@code persist()}: Hibernate would ask for the
     * generated id, which costs read access to the table on some databases (the
     * PostgreSQL driver appends {@code RETURNING *}). The id is not needed afterwards, so
     * the audit trail stays append-only for a database user that may insert rows but not
     * read them (the MCP instances of a split deployment,
     * {@code examples/split-deployment}).
     * <p>
     * The statement is plain SQL-92 and leaves {@code id} to the column's identity
     * default, so it runs on every database the changelog creates the table on. The
     * parameters carry the column names and are bound with their Java type, so a
     * {@code null} is bound as a null of that type instead of whatever the dialect picks
     * for an untyped one.
     */
    static final String INSERT = """
            insert into kc_mcp_audit_event (occurred_at, tool, level, system_alias, realm, args, outcome, message,
                via, caller_subject, caller_name, caller_realm, delegated, client_name, connection_id, duration_ms)
            values (:occurred_at, :tool, :level, :system_alias, :realm, :args, :outcome, :message,
                :via, :caller_subject, :caller_name, :caller_realm, :delegated, :client_name, :connection_id,
                :duration_ms)
            """;

    @Override
    @Transactional
    public void onToolCall(AuditEvent event) {
        AuditEventEntity.getEntityManager()
            .unwrap(Session.class)
            .createNativeMutationQuery(INSERT)
            .setParameter("occurred_at", event.at() == null ? System.currentTimeMillis() : event.at().toEpochMilli(),
                    Long.class)
            .setParameter("tool", event.tool(), String.class)
            .setParameter("level", event.level() == null ? "READ" : event.level().name(), String.class)
            .setParameter("system_alias", event.system(), String.class)
            .setParameter("realm", event.realm(), String.class)
            .setParameter("args", event.args().isEmpty() ? null : new JsonObject(event.args()).encode(), String.class)
            .setParameter("outcome", event.outcome(), String.class)
            .setParameter("message", event.message(), String.class)
            .setParameter("via", event.via(), String.class)
            .setParameter("caller_subject", event.caller().subject(), String.class)
            .setParameter("caller_name", event.caller().name(), String.class)
            .setParameter("caller_realm", event.caller().realm(), String.class)
            .setParameter("delegated", event.caller().delegated(), Boolean.class)
            .setParameter("client_name", event.clientName(), String.class)
            .setParameter("connection_id", event.connectionId(), String.class)
            .setParameter("duration_ms", event.duration() == null ? 0L : event.duration().toMillis(), Long.class)
            .executeUpdate();
    }

    /** The newest events, newest first. */
    @Transactional
    public List<AuditEventEntity> recent(int limit) {
        return AuditEventEntity.findAll(Sort.descending("occurredAt", "id")).page(0, Math.max(1, limit)).list();
    }

    /** The newest events of one caller (token {@code sub}), newest first. */
    @Transactional
    public List<AuditEventEntity> byCaller(String subject, int limit) {
        return AuditEventEntity.find("callerSubject = ?1", Sort.descending("occurredAt", "id"), subject)
            .page(0, Math.max(1, limit))
            .list();
    }

    @Transactional
    public long count() {
        return AuditEventEntity.count();
    }

    /**
     * Deletes the events that occurred before a moment (epoch milliseconds) and returns
     * how many; one statement on the {@code occurred_at} index.
     */
    @Transactional
    public long purgeOlderThan(long cutoffMillis) {
        return AuditEventEntity.delete("occurredAt < ?1", cutoffMillis);
    }
}
