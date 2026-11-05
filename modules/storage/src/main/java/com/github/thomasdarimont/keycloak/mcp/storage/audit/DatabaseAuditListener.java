package com.github.thomasdarimont.keycloak.mcp.storage.audit;

import java.util.List;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.transaction.Transactional;

import com.github.thomasdarimont.keycloak.mcp.audit.AuditEvent;
import com.github.thomasdarimont.keycloak.mcp.audit.AuditListener;
import com.github.thomasdarimont.keycloak.mcp.storage.StorageConfigSourceFactory;

import io.quarkus.arc.lookup.LookupIfProperty;
import io.quarkus.panache.common.Sort;
import io.vertx.core.json.JsonObject;

/**
 * Writes one {@code kc_mcp_audit_event} row per finished tool call, synchronously on the
 * handler's thread so the record exists before the result leaves the server; a database
 * failure is logged by the server and does not change the tool result. Arguments arrive
 * redacted; personal data is the {@link PiiAuditScrubber}'s business. Rows are kept until
 * {@link AuditRetention} removes them ({@code kc-mcp.spi.db-audit.retention-days}, off by
 * default). Switch it off alone with {@code kc-mcp.spi.db-audit.enabled=false}.
 */
@ApplicationScoped
@LookupIfProperty(name = StorageConfigSourceFactory.ENABLED, stringValue = "true")
public class DatabaseAuditListener implements AuditListener {

    public static final String ID = "db-audit";

    @Override
    public String id() {
        return ID;
    }

    @Override
    public String displayName() {
        return "Database audit log";
    }

    @Override
    public String description() {
        return "one kc_mcp_audit_event row per tool call";
    }

    @Override
    @Transactional
    public void onToolCall(AuditEvent event) {
        AuditEventEntity e = new AuditEventEntity();
        e.occurredAt = event.at() == null ? System.currentTimeMillis() : event.at().toEpochMilli();
        e.tool = event.tool();
        e.level = event.level() == null ? "READ" : event.level().name();
        e.system = event.system();
        e.realm = event.realm();
        e.args = event.args().isEmpty() ? null : new JsonObject(event.args()).encode();
        e.outcome = event.outcome();
        e.message = event.message();
        e.via = event.via();
        e.callerSubject = event.caller().subject();
        e.callerName = event.caller().name();
        e.callerRealm = event.caller().realm();
        e.delegated = event.caller().delegated();
        e.clientName = event.clientName();
        e.connectionId = event.connectionId();
        e.durationMs = event.duration() == null ? 0 : event.duration().toMillis();
        e.persist();
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
