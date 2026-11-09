package com.github.thomasdarimont.keycloak.mcp.backend.metrics;

import java.util.ArrayList;
import java.util.List;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;

import io.quarkiverse.mcp.server.McpConnection;
import io.quarkiverse.mcp.server.runtime.ConnectionManager;
import io.quarkus.runtime.StartupEvent;

/**
 * Registers the gauge of open MCP sessions: the connection manager of quarkus-mcp-server
 * knows them, each with the client's name from {@code initialize}. Transient connections
 * (stateless requests without a session) are not counted.
 */
@ApplicationScoped
public class SessionMetrics {

    @Inject
    KcMcpMetrics metrics;
    @Inject
    Instance<ConnectionManager> connections;

    void onStart(@Observes StartupEvent event) {
        if (!connections.isResolvable()) {
            return;
        }
        ConnectionManager manager = connections.get();
        metrics.mcpConnections(() -> clients(manager));
    }

    static List<String> clients(Iterable<? extends McpConnection> connections) {
        List<String> out = new ArrayList<>();
        for (McpConnection c : connections) {
            if (c.isTransient()) {
                continue;
            }
            out.add(c.initialRequest() == null || c.initialRequest().implementation() == null ? "-"
                    : c.initialRequest().implementation().name());
        }
        return out;
    }
}
