package com.github.thomasdarimont.keycloak.mcp.backend.keycloak;

import java.util.Optional;
import java.util.Set;
import jakarta.ws.rs.client.ClientRequestContext;
import jakarta.ws.rs.client.ClientRequestFilter;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.jboss.logging.Logger;

/**
 * Holds a tool that says it only reads to its word. While a {@code READ} tool's handler
 * runs ({@link #run}), the admin clients refuse every request to the Admin API
 * ({@code /admin/...}) that is not {@code GET}, {@code HEAD} or {@code OPTIONS}: the
 * request is not sent, and the violation is recorded, so that the call fails as
 * {@code read_only_violation} even when the tool catches the error. Token requests are
 * not under {@code /admin/} and pass.
 * <p>
 * This catches mislabelled tools and mistakes; it is no sandbox. An extension is code in
 * the server's process, which can build its own HTTP client or read the server's secrets:
 * installing one is a decision of trust, as with a Keycloak provider. Work a tool hands
 * to a thread of its own escapes the guard unless that thread inherits it (threads
 * created from the handler's thread do; pooled threads do not).
 */
public final class ReadOnlyGuard implements ClientRequestFilter {

    private static final Logger LOG = Logger.getLogger(ReadOnlyGuard.class);

    static final Set<String> SAFE = Set.of("GET", "HEAD", "OPTIONS");

    /** The read-only call on this thread and what it tried. */
    private static final class Call {
        final String tool;
        volatile String violation;

        Call(String tool) {
            this.tool = tool;
        }
    }

    private static final InheritableThreadLocal<Call> CURRENT = new InheritableThreadLocal<>();

    /**
     * The outcome of a guarded run: the body's result and what was refused, if anything.
     */
    public record Outcome<T>(T result, Optional<String> violation) {
    }

    /** A handler, which may throw what tools throw. */
    @FunctionalInterface
    public interface Body<T> {
        T get() throws Exception;
    }

    /** Runs a read-only tool's handler with the guard on. */
    public static <T> Outcome<T> run(String tool, Body<T> body) throws Exception {
        Call previous = CURRENT.get();
        Call call = new Call(tool);
        CURRENT.set(call);
        try {
            T result = body.get();
            return new Outcome<>(result, Optional.ofNullable(call.violation));
        }
        catch (Exception e) {
            if (call.violation != null) {
                // the refusal surfaced as the tool's exception: the violation is the
                // story
                return new Outcome<>(null, Optional.of(call.violation));
            }
            throw e;
        }
        finally {
            if (previous == null) {
                CURRENT.remove();
            }
            else {
                CURRENT.set(previous);
            }
        }
    }

    @Override
    public void filter(ClientRequestContext request) {
        Call call = CURRENT.get();
        if (call == null || SAFE.contains(request.getMethod())) {
            return;
        }
        String path = request.getUri().getRawPath();
        if (path == null || !path.contains("/admin/")) {
            return;
        }
        String what = request.getMethod() + " " + path;
        if (call.violation == null) {
            call.violation = what;
        }
        LOG.errorf("Tool %s declares that it only reads, but sent %s; refused", call.tool, what);
        request.abortWith(Response.status(Response.Status.FORBIDDEN)
            .type(MediaType.APPLICATION_JSON_TYPE)
            .entity("{\"error\":\"read_only_violation\",\"error_description\":\"" + call.tool
                    + " is declared read-only\"}")
            .build());
    }
}
