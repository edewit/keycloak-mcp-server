package com.github.thomasdarimont.keycloak.mcp.backend.ciba;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import jakarta.enterprise.context.ApplicationScoped;

import com.github.thomasdarimont.keycloak.mcp.confirm.PendingApproval;
import com.github.thomasdarimont.keycloak.mcp.confirm.PendingApprovalStore;

/**
 * The fallback {@link PendingApprovalStore}: this instance's memory. Fine for one server;
 * with several, the database storage's {@code db-approvals} is used instead (lower
 * order).
 */
@ApplicationScoped
public class InMemoryPendingApprovalStore implements PendingApprovalStore {

    public static final String ID = "memory-approvals";

    private final Map<String, PendingApproval> entries = new ConcurrentHashMap<>();

    @Override
    public String id() {
        return ID;
    }

    @Override
    public String displayName() {
        return "Pending approvals in memory";
    }

    @Override
    public String description() {
        return "Keeps the CIBA confirmer's pending approvals in this instance's memory (single instance).";
    }

    @Override
    public int order() {
        return 1000;
    }

    @Override
    public boolean reserve(String key, long until) {
        PendingApproval placeholder = new PendingApproval(key, null, null, null, null, null, null, null, null, null,
                null, null, until, 0, System.currentTimeMillis());
        PendingApproval current = entries.compute(key,
                (k, existing) -> existing == null || existing.expired() ? placeholder : existing);
        return current == placeholder;
    }

    @Override
    public void put(PendingApproval approval) {
        entries.put(approval.key(), approval);
    }

    @Override
    public Optional<PendingApproval> find(String key) {
        PendingApproval p = entries.get(key);
        if (p != null && p.expired()) {
            entries.remove(key, p);
            return Optional.empty();
        }
        return Optional.ofNullable(p);
    }

    @Override
    public boolean remove(String key) {
        PendingApproval p = entries.remove(key);
        return p != null && !p.expired();
    }

    @Override
    public long deleteExpired(long now) {
        long before = entries.size();
        entries.values().removeIf(p -> p.expiresAt() <= now);
        return before - entries.size();
    }

    @Override
    public long countLive(long now) {
        return entries.values().stream().filter(p -> p.expiresAt() > now).count();
    }

    public int size() {
        deleteExpired(System.currentTimeMillis());
        return entries.size();
    }
}
