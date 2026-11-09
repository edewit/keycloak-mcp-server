package com.github.thomasdarimont.keycloak.mcp.backend.http;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;

import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;

import com.github.thomasdarimont.keycloak.mcp.config.McpServerConfig;

import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;

/**
 * Switches the OpenAPI document and Swagger UI off at runtime: Quarkus decides at build
 * time whether to serve them, so {@code kc-mcp.admin.openapi=false} answers 404 for
 * {@code <non-application root>/openapi} and {@code /swagger-ui} ahead of their handlers.
 */
@ApplicationScoped
public class OpenApiRoutes {

    private static final Logger LOG = Logger.getLogger(OpenApiRoutes.class);

    @Inject
    McpServerConfig config;
    @ConfigProperty(name = "quarkus.http.non-application-root-path", defaultValue = "q")
    String nonApplicationRoot;

    void register(@Observes Router router) {
        if (config.admin().openapi()) {
            return;
        }
        String root = EntryRoutes.root("/" + nonApplicationRoot.replaceFirst("^/+", ""));
        for (String path : new String[] { root + "/openapi", root + "/swagger-ui" }) {
            router.route(path).order(-1000).handler(OpenApiRoutes::notFound);
            router.route(path + "/*").order(-1000).handler(OpenApiRoutes::notFound);
        }
        LOG.infof("OpenAPI document and Swagger UI off (kc-mcp.admin.openapi=false)");
    }

    private static void notFound(RoutingContext ctx) {
        ctx.response().setStatusCode(404).end();
    }
}
