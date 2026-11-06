package com.github.thomasdarimont.keycloak.mcp.backend.ciba;

import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import jakarta.enterprise.context.ApplicationScoped;

import com.github.thomasdarimont.keycloak.mcp.confirm.PendingApproval;
import com.github.thomasdarimont.keycloak.mcp.confirm.PendingApprovalStore;

/**
 * The fallback {@link PendingApprovalStore}: this instance's memory. Fine for one server;
 * with several, the database storage's {@code db-approvals} is used instead (lower
 * order). Every operation is one atomic {@code compute} on the key.
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
    public Optional<String> reserve(String key, long until) {
        String generation = UUID.randomUUID().toString();
        PendingApproval mine = PendingApproval.reservation(key, generation, until);
        PendingApproval current = entries.compute(key,
                (k, existing) -> existing == null || existing.expired() ? mine : existing);
        return current == mine ? Optional.of(generation) : Optional.empty();
    }

    @Override
    public boolean put(PendingApproval approval) {
        AtomicBoolean stored = new AtomicBoolean();
        entries.computeIfPresent(approval.key(), (k, existing) -> {
            if (existing.generation().equals(approval.generation()) && !existing.expired()) {
                stored.set(true);
                return approval;
            }
            return existing;
        });
        return stored.get();
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
    public boolean claim(String key, String generation, String collector, long until) {
        AtomicBoolean claimed = new AtomicBoolean();
        long now = System.currentTimeMillis();
        entries.computeIfPresent(key, (k, existing) -> {
            if (!existing.generation().equals(generation) || existing.expired()
                    || existing.claimedByOther(collector, now)) {
                return existing;
            }
            claimed.set(true);
            return existing.withClaim(collector, until);
        });
        return claimed.get();
    }

    @Override
    public boolean markApproved(String key, String generation) {
        AtomicBoolean marked = new AtomicBoolean();
        entries.computeIfPresent(key, (k, existing) -> {
            if (!existing.generation().equals(generation) || existing.expired()) {
                return existing;
            }
            marked.set(true);
            return existing.asApproved();
        });
        return marked.get();
    }

    @Override
    public void release(String key, String generation, String collector) {
        entries.computeIfPresent(key,
                (k, existing) -> existing.generation().equals(generation) && collector.equals(existing.claimedBy())
                        ? existing.withClaim(null, 0) : existing);
    }

    @Override
    public boolean remove(String key, String generation) {
        AtomicBoolean removed = new AtomicBoolean();
        entries.computeIfPresent(key, (k, existing) -> {
            if (!existing.generation().equals(generation)) {
                return existing;
            }
            removed.set(!existing.expired());
            return null;
        });
        return removed.get();
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
