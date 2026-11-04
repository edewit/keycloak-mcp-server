package org.keycloak.mcp.server.search;

import org.keycloak.mcp.catalog.ToolSpec;

public record SearchHit(ToolSpec spec, int score) {
}
