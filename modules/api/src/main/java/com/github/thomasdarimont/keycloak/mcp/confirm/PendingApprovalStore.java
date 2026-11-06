package com.github.thomasdarimont.keycloak.mcp.confirm;

import java.util.Optional;

import com.github.thomasdarimont.keycloak.mcp.spi.Extension;

/**
 * Keeps the {@link PendingApproval}s of the CIBA confirmer, so the call that collects a
 * decision finds the request the previous call filed, on this or another instance. The
 * database storage provides one ({@code db-approvals}); the server falls back to an
 * in-memory store ({@code memory-approvals}, single instance). The store with the lowest
 * {@link #order()} is used. Implementations are called concurrently from worker threads.
 */
public interface PendingApprovalStore extends Extension {

    /**
     * Claims the key for a request about to be filed, atomically across instances:
     * {@code true} when nobody holds it, or the holder has expired, so that exactly one
     * caller files the request; {@code false} when a live reservation or approval exists.
     *
     * @param until epoch milliseconds the bare reservation lasts; {@link #put} replaces
     * it with the approval's own expiry
     */
    boolean reserve(String key, long until);

    /** Stores the filed approval under its key (which {@link #reserve} claimed). */
    void put(PendingApproval approval);

    /**
     * The live approval under this key, reserved or filed; empty when none or expired.
     */
    Optional<PendingApproval> find(String key);

    /**
     * Consumes the approval: {@code true} when this call removed a live entry, so that a
     * decision is acted on once even when two calls collect it at the same time.
     */
    boolean remove(String key);

    /** Removes entries past their expiry; how many. */
    long deleteExpired(long now);

    /**
     * How many live entries there are (for the pending gauge); negative when the store
     * cannot tell.
     */
    default long countLive(long now) {
        return -1;
    }
}
