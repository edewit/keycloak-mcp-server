package com.github.thomasdarimont.keycloak.mcp.backend.http;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;

import org.jboss.logging.Logger;

import com.github.thomasdarimont.keycloak.mcp.config.McpServerConfig;

import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;

/**
 * {@code kc-mcp.mcp.enabled=false}: the MCP endpoint and its entries answer a plain 404
 * ahead of every other handler, so an instance can serve the admin API or the management
 * UI alone, next to the MCP-facing instances on the same database. The answer says
 * nothing about why, or about what else this instance serves: the startup log does. The
 * routes are on the application router, so they follow {@code quarkus.http.root-path}.
 */
@ApplicationScoped
public class McpEndpointSwitch {

    private static final Logger LOG = Logger.getLogger(McpEndpointSwitch.class);

    @Inject
    McpServerConfig config;
    @Inject
    HttpPaths paths;

    void register(@Observes Router router) {
        if (config.mcp().enabled()) {
            return;
        }
        String root = paths.mcpRoot();
        router.route(root).order(-1000).handler(McpEndpointSwitch::disabled);
        router.route(root + "/*").order(-1000).handler(McpEndpointSwitch::disabled);
        LOG.infof("MCP endpoint off (kc-mcp.mcp.enabled=false): this instance serves the admin API%s only",
                config.ui().enabled() ? " and the management UI" : "");
    }

    private static void disabled(RoutingContext ctx) {
        ctx.response()
            .setStatusCode(404)
            .putHeader("Content-Type", "application/json")
            .end("{\"error\":\"not_found\",\"message\":\"Not found.\"}");
    }
}
