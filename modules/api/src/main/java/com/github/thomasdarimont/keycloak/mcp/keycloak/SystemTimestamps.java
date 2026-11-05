package com.github.thomasdarimont.keycloak.mcp.keycloak;

import java.time.Instant;

/**
 * When a repository created and last changed a system's record; what the admin API shows
 * as {@code createdAt} and {@code updatedAt}. Repositories without such bookkeeping
 * (static configuration) report none.
 */
public record SystemTimestamps(Instant createdAt, Instant updatedAt) {
}
