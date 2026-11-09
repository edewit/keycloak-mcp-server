package com.github.thomasdarimont.keycloak.mcp.backend.ui;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;

import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;

import com.github.thomasdarimont.keycloak.mcp.backend.metrics.KcMcpMetrics;
import com.github.thomasdarimont.keycloak.mcp.config.McpServerConfig;
import com.github.thomasdarimont.keycloak.mcp.web.UserSessionStore;

import io.quarkus.runtime.StartupEvent;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.http.HttpMethod;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;

/**
 * Serves the management UI SPA under {@code /ui}: Quarkus Web Bundler renders
 * {@code frontend/index.html} (with {@code {#bundle /}}) into
 * {@code META-INF/resources/index.html}. {@code /ui} goes to {@code /ui/}, and
 * extension-less paths ({@code /ui/systems}) get that index with
 * {@code Cache-Control: no-cache} so the browser picks up hashed bundles after a rebuild.
 * Bundle assets under {@code /static/bundle/} are served from the class path when they
 * are there, which the static handler cannot do for the jar of a Maven-built distribution
 * ({@code modules/ui-bundle}): its list of files is made at build time and misses them; a
 * bundle only Web Bundler's dev mode knows passes on to it. Web Bundler also publishes
 * the index at {@code /}; this class redirects that to {@code /ui/} when the UI is on and
 * answers 404 when it is off, so the product entry stays {@code /ui}. At startup a
 * {@link UserSessionStore} must be registered, else the server does not start; a missing
 * index is reported.
 */
@ApplicationScoped
public class UiRoutes {

    private static final Logger LOG = Logger.getLogger(UiRoutes.class);
    /**
     * Web Bundler output of {@code frontend/index.html}; served for every SPA route under
     * {@code /ui}.
     */
    static final String INDEX = "META-INF/resources/index.html";

    @Inject
    McpServerConfig config;
    @Inject
    UserSessionTokenStateManager sessions;
    @Inject
    UiTenant tenant;
    @ConfigProperty(name = "quarkus.http.ssl-port", defaultValue = "8443")
    int sslPort;
    @ConfigProperty(name = "quarkus.http.port", defaultValue = "8080")
    int httpPort;

    private volatile byte[] indexPage;
    private final Map<String, byte[]> bundleFiles = new ConcurrentHashMap<>();

    @Inject
    KcMcpMetrics metrics;

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
            LOG.warnf("Management UI: no index on the class path (%s); the BFF under %s works, %s/ answers 404", INDEX,
                    UiTenant.BFF_PATH, UiTenant.UI_PATH);
        }
        List<UiTenant.Idp> idps = tenant.idps();
        if (idps.isEmpty()) {
            throw new IllegalStateException("kc-mcp.ui.enabled=true needs an identity provider: kc-mcp.ui.issuer or"
                    + " kc-mcp.ui.idps.<alias>.issuer.");
        }
        UserSessionStore kept = store.get();
        metrics.uiSessions(() -> kept.countLive(System.currentTimeMillis()));
        String location = config.devMode() ? "http://<host>:%d%s/ (https port %d with a certificate)".formatted(
                httpPort, UiTenant.UI_PATH, sslPort) : "https://<host>:%d%s/".formatted(sslPort, UiTenant.UI_PATH);
        LOG.infof("Management UI at %s, sessions kept by %s; identity providers: %s", location, store.get().id(),
                idps.stream().map(UiTenant.Idp::describe).toList());
    }

    void register(@Observes Router router) {
        // Ahead of the static handler: Web Bundler puts the SPA index at / as well as
        // under /ui.
        router.route(HttpMethod.GET, "/").order(-2000).handler(this::root);
        router.route(HttpMethod.GET, "/index.html").order(-2000).handler(this::root);
        router.route(HttpMethod.GET, "/static/bundle/*").order(-2000).handler(this::bundle);
        // Vert.x lets the exact path /ui match /ui/ as well, so one handler sorts both
        // out
        router.route(HttpMethod.GET, UiTenant.UI_PATH).handler(this::serve);
        router.route(HttpMethod.GET, UiTenant.UI_PATH + "/*").handler(this::serve);
    }

    /** A file of the bundle, read once; anything not on the class path passes on. */
    private void bundle(RoutingContext ctx) {
        String path = ctx.normalizedPath();
        byte[] file = config.ui().enabled() && !path.contains("..") ? bundleFile(path) : null;
        if (file == null) {
            ctx.next();
            return;
        }
        ctx.response()
            .putHeader("Content-Type", contentType(path))
            .putHeader("Cache-Control", "public, max-age=86400")
            .end(Buffer.buffer(file));
    }

    private byte[] bundleFile(String path) {
        byte[] file = bundleFiles.get(path);
        if (file != null) {
            return file;
        }
        try (InputStream in = Thread.currentThread()
            .getContextClassLoader()
            .getResourceAsStream("META-INF/resources" + path)) {
            if (in == null) {
                return null;
            }
            file = in.readAllBytes();
        }
        catch (IOException e) {
            LOG.warnf("Cannot read %s: %s", path, e.getMessage());
            return null;
        }
        bundleFiles.put(path, file);
        return file;
    }

    static String contentType(String path) {
        String extension = path.substring(path.lastIndexOf('.') + 1);
        return switch (extension) {
            case "js" -> "text/javascript;charset=UTF-8";
            case "css" -> "text/css;charset=UTF-8";
            case "map" -> "application/json";
            default -> "application/octet-stream";
        };
    }

    /**
     * Web Bundler's default index is at {@code /}; keep the product entry at {@code /ui}.
     */
    private void root(RoutingContext ctx) {
        if (index() == null) {
            ctx.next();
            return;
        }
        if (!config.ui().enabled()) {
            off(ctx);
            return;
        }
        ctx.response().setStatusCode(302).putHeader("Location", UiTenant.UI_PATH + "/").end();
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
                    .end("{\"error\":\"ui_missing\",\"message\":\"The management UI index is not on the class path.\"}");
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

    /**
     * The Web Bundler–rendered SPA page, read once; {@code null} if bundling did not
     * produce it.
     */
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
