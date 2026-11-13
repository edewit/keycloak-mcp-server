package com.github.thomasdarimont.keycloak.mcp.web;

import java.util.Optional;

import com.github.thomasdarimont.keycloak.mcp.spi.Extension;

/**
 * Keeps the sessions of the management UI ({@link UserSession}) on the server, so the
 * browser cookie carries an opaque id and never a token, and a session can be revoked by
 * deleting its row. The database storage provides one ({@code db}); register your own
 * ({@code @AutoService(UserSessionStore.class)} or a CDI bean) to keep sessions
 * elsewhere, say in Redis or Infinispan. The store with the lowest {@link #order()} is
 * used. Implementations are called from worker threads and must be safe to call
 * concurrently.
 */
public interface UserSessionStore extends Extension {

    /**
     * This extension point's name in configuration keys:
     * {@code kc-mcp.spi.session-store.<id>.*}.
     */
    String SPI = "session-store";

    @Override
    default String spiName() {
        return SPI;
    }

    /** Stores a new session or replaces the one with the same id. */
    void save(UserSession session);

    /** The session with this id, if it exists and has not expired. */
    Optional<UserSession> find(String id);

    /** Removes a session; nothing happens when it is unknown. */
    void delete(String id);

    /**
     * Removes a session only while it still holds {@code refreshToken}: the session check
     * redeemed that token and the provider refused it, but with rotating refresh tokens
     * another request, on this instance or another one, may have renewed the session in
     * the meantime, and a renewed session must stay. Comparing and removing are one step,
     * so a renewal saved concurrently is either seen (the session stays) or saved after
     * the removal.
     * <p>
     * The default reads, compares and removes in separate calls, which leaves a short
     * window between them; stores shared by several instances should override it with an
     * atomic operation (a row lock, a compare-and-delete script, a versioned remove).
     *
     * @return the session as it is now when it was kept (renewed), empty when it was
     * removed or was gone already
     */
    default Optional<UserSession> deleteUnlessRenewed(String id, String refreshToken) {
        Optional<UserSession> now = find(id);
        if (now.isPresent() && !java.util.Objects.equals(now.get().refreshToken(), refreshToken)) {
            return now;
        }
        delete(id);
        return Optional.empty();
    }

    /**
     * Removes every session whose {@link UserSession#expiresAt()} lies before
     * {@code now}; how many.
     */
    long deleteExpired(long now);

    /**
     * Ends the sessions a back-channel logout of {@code issuer} names by the provider's
     * session id; how many.
     */
    long deleteBySession(String issuer, String sid);

    /**
     * Ends every session of a user at an issuer (a back-channel logout without
     * {@code sid}, an administrator revoking access); how many.
     */
    long deleteBySubject(String issuer, String subject);

    /**
     * How many unexpired sessions there are (for the session gauge); negative when the
     * store cannot tell.
     */
    default long countLive(long now) {
        return -1;
    }
}
