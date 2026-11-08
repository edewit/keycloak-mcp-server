package com.github.thomasdarimont.keycloak.mcp.backend.http;

import java.util.Optional;
import java.util.regex.Pattern;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;

import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;

import com.github.thomasdarimont.keycloak.mcp.backend.guard.EntryBinding;

import io.quarkus.arc.Arc;
import io.quarkus.arc.InstanceHandle;
import io.quarkus.vertx.http.runtime.CurrentVertxRequest;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;

/**
 * Logical MCP entries bound to one system or one realm: {@code <root>/systems/<system>}
 * and {@code <root>/systems/<system>/<realm>} ({@code root} is
 * {@code quarkus.mcp.server.http.root-path}, {@code /mcp}). The request is rerouted to
 * the one MCP handler with the {@link EntryBinding} attached, so a client configured with
 * such a URL cannot leave that system or realm: the invoker pins the {@code system} and
 * {@code realm} arguments, and the caller logs in against that system's realm
 * ({@link EntryTenantResolver}).
 */
@ApplicationScoped
public class EntryRoutes {

    private static final Logger LOG = Logger.getLogger(EntryRoutes.class);

    /** Path segment between the root and the system name. */
    public static final String SEGMENT = "systems";

    private static final Pattern NAME = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._~-]{0,99}");

    @ConfigProperty(name = "quarkus.mcp.server.http.root-path", defaultValue = "/mcp")
    String rootPath;
    @Inject
    HttpPaths paths;

    void register(@Observes Router router) {
        String base = root(rootPath) + "/" + SEGMENT + "/";
        router.route(base + ":system").handler(this::reroute);
        router.route(base + ":system/:realm").handler(this::reroute);
        LOG.infof("MCP entries per system at %s<system> and %s<system>/<realm>", base, base);
    }

    private void reroute(RoutingContext ctx) {
        // the router is mounted under the HTTP root path, the request path carries it
        Optional<EntryBinding> binding = resolveEntryBinding(paths.relative(ctx.request().path()), rootPath);
        if (binding.isEmpty()) {
            ctx.response()
                .setStatusCode(404)
                .putHeader("Content-Type", "application/json")
                .end("{\"error\":\"invalid_entry\",\"message\":\"Use /systems/<system> or /systems/<system>/<realm>.\"}");
            return;
        }
        ctx.put(EntryBinding.KEY, binding.get());
        // a reroute restarts at the top, so the target carries the HTTP root path
        ctx.reroute(ctx.request().method(), paths.absoluteMcpRoot());
    }

    /**
     * The binding a request path addresses, empty for the plain root or a malformed path.
     */
    public static Optional<EntryBinding> resolveEntryBinding(String path, String rootPath) {
        String base = root(rootPath) + "/" + SEGMENT + "/";
        if (path == null || !path.startsWith(base)) {
            return Optional.empty();
        }
        String rest = path.substring(base.length());
        if (rest.endsWith("/")) {
            rest = rest.substring(0, rest.length() - 1);
        }
        String[] parts = rest.split("/", -1);
        if (parts.length == 0 || parts.length > 2) {
            return Optional.empty();
        }
        for (String p : parts) {
            if (!NAME.matcher(p).matches()) {
                return Optional.empty();
            }
        }
        return Optional.of(new EntryBinding(parts[0], parts.length == 2 ? parts[1] : null));
    }

    /**
     * The binding of the current HTTP request, empty outside a request or on the plain
     * root.
     */
    public static Optional<EntryBinding> current() {
        try {
            if (!Arc.container().requestContext().isActive()) {
                return Optional.empty();
            }
            InstanceHandle<CurrentVertxRequest> handle = Arc.container().instance(CurrentVertxRequest.class);
            if (!handle.isAvailable()) {
                return Optional.empty();
            }
            RoutingContext rc = handle.get().getCurrent();
            return rc == null ? Optional.empty() : Optional.ofNullable(rc.get(EntryBinding.KEY));
        }
        catch (RuntimeException e) {
            LOG.debugf("No request binding available: %s", e.toString());
            return Optional.empty();
        }
    }

    public static String root(String rootPath) {
        String r = rootPath == null || rootPath.isBlank() ? "/mcp" : rootPath.trim();
        if (!r.startsWith("/")) {
            r = "/" + r;
        }
        return r.endsWith("/") ? r.substring(0, r.length() - 1) : r;
    }
}
