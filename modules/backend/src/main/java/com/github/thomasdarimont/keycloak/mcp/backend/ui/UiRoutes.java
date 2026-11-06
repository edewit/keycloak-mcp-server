package com.github.thomasdarimont.keycloak.mcp.backend.ui;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.Optional;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;

import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;

import com.github.thomasdarimont.keycloak.mcp.config.McpServerConfig;
import com.github.thomasdarimont.keycloak.mcp.web.UserSessionStore;

import io.quarkus.runtime.StartupEvent;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.http.HttpMethod;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;

/**
 * Serves the management UI, a single-page application from the
 * {@code keycloak-mcp-server-frontend} jar ({@code META-INF/resources/ui}): {@code /ui}
 * goes to {@code /ui/}, and a path without a file extension ({@code /ui/systems}) gets
 * {@code index.html}, served from the jar with {@code Cache-Control: no-cache} because it
 * names the hashed bundles of its build, so the browser can reload any route of the app
 * and never keeps a page of an earlier build. Files keep their paths and the static
 * handler's caching. With the UI off everything under {@code /ui} is 404. At startup the
 * UI's prerequisites are checked: a {@link UserSessionStore} must be registered, else the
 * server does not start, and a missing frontend jar is reported.
 */
@ApplicationScoped
public class UiRoutes {

    private static final Logger LOG = Logger.getLogger(UiRoutes.class);
    static final String INDEX = "META-INF/resources" + UiTenant.UI_PATH + "/index.html";

    @Inject
    McpServerConfig config;
    @Inject
    UserSessionTokenStateManager sessions;
    @Inject
    UiTenant tenant;
    @ConfigProperty(name = "quarkus.http.ssl-port", defaultValue = "8443")
    int sslPort;

    private volatile byte[] indexPage;

    void onStart(@Observes StartupEvent event) {
        if (!config.ui().enabled()) {
            LOG.debug("Management UI off (kc-mcp.ui.enabled)");
            return;
        }
        Optional<UserSessionStore> store = sessions.resolve();
        if (store.isEmpty()) {
            throw new IllegalStateException("kc-mcp.ui.enabled=true needs a UserSessionStore for the browser"
                    + " sessions: configure the database storage (quarkus.datasource.jdbc.url) or register one.");
        }
        if (index() == null) {
            LOG.warnf("Management UI: no frontend on the class path (%s); the BFF under %s works, %s/ answers 404",
                    INDEX, UiTenant.BFF_PATH, UiTenant.UI_PATH);
        }
        List<UiTenant.Idp> idps = tenant.idps();
        if (idps.isEmpty()) {
            throw new IllegalStateException("kc-mcp.ui.enabled=true needs an identity provider: kc-mcp.ui.issuer or"
                    + " kc-mcp.ui.idps.<alias>.issuer.");
        }
        LOG.infof("Management UI at https://<host>:%d%s/, sessions kept by %s; identity providers: %s", sslPort,
                UiTenant.UI_PATH, store.get().id(), idps.stream().map(UiTenant.Idp::describe).toList());
    }

    void register(@Observes Router router) {
        // Vert.x lets the exact path /ui match /ui/ as well, so one handler sorts both
        // out
        router.route(HttpMethod.GET, UiTenant.UI_PATH).handler(this::serve);
        router.route(HttpMethod.GET, UiTenant.UI_PATH + "/*").handler(this::serve);
    }

    /**
     * {@code /ui} goes to {@code /ui/}; routes of the app get the page; files pass to the
     * static handler.
     */
    private void serve(RoutingContext ctx) {
        if (!config.ui().enabled()) {
            off(ctx);
            return;
        }
        String path = ctx.normalizedPath();
        if (path.equals(UiTenant.UI_PATH)) {
            ctx.response().setStatusCode(302).putHeader("Location", UiTenant.UI_PATH + "/").end();
            return;
        }
        if (isIndexRoute(path)) {
            byte[] page = index();
            if (page == null) {
                ctx.response()
                    .setStatusCode(404)
                    .putHeader("Content-Type", "application/json")
                    .end("{\"error\":\"ui_missing\",\"message\":\"The frontend is not on the class path.\"}");
                return;
            }
            ctx.response()
                .putHeader("Content-Type", "text/html; charset=utf-8")
                .putHeader("Cache-Control", "no-cache")
                .end(Buffer.buffer(page));
            return;
        }
        ctx.next();
    }

    /** {@code /ui/} and extension-less paths below it, which are routes of the app. */
    static boolean isIndexRoute(String path) {
        String rest = path.substring(UiTenant.UI_PATH.length() + 1);
        if (rest.isEmpty()) {
            return true;
        }
        String last = rest.substring(rest.lastIndexOf('/') + 1);
        return !last.contains(".");
    }

    /** The app's page from the frontend jar, read once; {@code null} without the jar. */
    private byte[] index() {
        byte[] page = indexPage;
        if (page == null) {
            try (InputStream in = Thread.currentThread().getContextClassLoader().getResourceAsStream(INDEX)) {
                page = in == null ? null : in.readAllBytes();
            }
            catch (IOException e) {
                LOG.warnf("Cannot read %s: %s", INDEX, e.getMessage());
                return null;
            }
            indexPage = page;
        }
        return page;
    }

    private static void off(RoutingContext ctx) {
        ctx.response()
            .setStatusCode(404)
            .putHeader("Content-Type", "application/json")
            .end("{\"error\":\"ui_disabled\",\"message\":\"The management UI is off (kc-mcp.ui.enabled).\"}");
    }
}
