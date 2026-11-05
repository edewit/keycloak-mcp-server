package com.github.thomasdarimont.keycloak.mcp.backend.admin;

import java.util.Map;

/**
 * The outcome of a PUT on the admin API: the representation to answer with and whether
 * something of that name existed before (200) or not (201).
 */
public record Saved(Map<String, Object> representation, boolean replaced) {
}
