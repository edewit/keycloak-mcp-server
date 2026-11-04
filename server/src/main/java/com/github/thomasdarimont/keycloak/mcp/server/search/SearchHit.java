package com.github.thomasdarimont.keycloak.mcp.server.search;

import com.github.thomasdarimont.keycloak.mcp.catalog.ToolSpec;

public record SearchHit(ToolSpec spec, int score) {
}
