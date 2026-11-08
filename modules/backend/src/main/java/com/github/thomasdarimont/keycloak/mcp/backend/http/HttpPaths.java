package com.github.thomasdarimont.keycloak.mcp.backend.http;

import jakarta.enterprise.context.ApplicationScoped;

import org.eclipse.microprofile.config.inject.ConfigProperty;

/**
 * The paths of this server as a client sees them. Quarkus mounts the application under
 * {@code quarkus.http.root-path} ({@code /} by default): routes registered on the
 * application router, resource metadata paths and JAX-RS paths are relative to it, while
 * a request's path and the absolute patterns of {@code quarkus.http.auth.permission} are
 * not. Everything that compares a request path with the MCP root, the admin API or the
 * entries goes through here, so a server behind a prefix behaves like one at the root.
 */
@ApplicationScoped
public class HttpPaths {

    @ConfigProperty(name = "quarkus.http.root-path", defaultValue = "/")
    String httpRootPath;
    @ConfigProperty(name = "quarkus.mcp.server.http.root-path", defaultValue = "/mcp")
    String mcpRootPath;

    /**
     * {@code ""} at the root, else the prefix without a trailing slash ({@code /prefix}).
     */
    public String httpRoot() {
        String r = httpRootPath == null ? "" : httpRootPath.trim();
        if (!r.startsWith("/")) {
            r = "/" + r;
        }
        while (r.endsWith("/")) {
            r = r.substring(0, r.length() - 1);
        }
        return r;
    }

    /** The MCP root relative to the HTTP root ({@code /mcp}): for routes and metadata. */
    public String mcpRoot() {
        return EntryRoutes.root(mcpRootPath);
    }

    /** The MCP root as a client addresses it ({@code /prefix/mcp}). */
    public String absoluteMcpRoot() {
        return httpRoot() + mcpRoot();
    }

    /**
     * A client-facing path for a root-relative one ({@code /auth/...} to
     * {@code /prefix/auth/...}).
     */
    public String absolute(String relativePath) {
        return httpRoot() + relativePath;
    }

    /**
     * A request path made relative to the HTTP root, {@code null} when it is outside it
     * ({@code /prefix/mcp/systems/a} to {@code /mcp/systems/a}).
     */
    public String relative(String requestPath) {
        if (requestPath == null) {
            return null;
        }
        String root = httpRoot();
        if (root.isEmpty()) {
            return requestPath;
        }
        if (requestPath.equals(root)) {
            return "/";
        }
        return requestPath.startsWith(root + "/") ? requestPath.substring(root.length()) : null;
    }

    /** Whether a request path is the MCP endpoint or anything under it (the entries). */
    public boolean underMcp(String requestPath) {
        String rel = relative(requestPath);
        String mcp = mcpRoot();
        return rel != null && (rel.equals(mcp) || rel.startsWith(mcp + "/"));
    }
}
