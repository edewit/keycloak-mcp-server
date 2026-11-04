package org.keycloak.mcp.guard;

import org.keycloak.mcp.spi.Caller;

import io.quarkiverse.mcp.server.Elicitation;
import io.quarkiverse.mcp.server.McpConnection;
import io.quarkiverse.mcp.server.McpLog;
import io.quarkiverse.mcp.server.ToolManager.ToolArguments;

/**
 * What the invoker needs from the transport layer. Decoupled from {@link ToolArguments}
 * so unit tests can fake it.
 *
 * @param via "direct" or "execute_tool", for the audit log
 * @param caller who acts through the connection; {@link Caller#NONE} until the endpoint
 * authenticates callers
 * @param callerToken the caller's raw access token, or {@code null}; forwarded to
 * Keycloak in delegation mode {@code forward}. Deliberately not part of {@link Caller},
 * which is shown to policies and logs.
 */
public record InvocationContext(McpConnection connection, Elicitation elicitation, McpLog log, String via,
        Caller caller, String callerToken) {

    public InvocationContext {
        caller = caller == null ? Caller.NONE : caller;
        callerToken = callerToken != null ? callerToken : caller.rawToken();
    }

    public InvocationContext(McpConnection connection, Elicitation elicitation, McpLog log, String via, Caller caller) {
        this(connection, elicitation, log, via, caller, null);
    }

    public static InvocationContext of(ToolArguments args, String via) {
        return new InvocationContext(args.connection(), args.elicitation(), args.log(), via, Caller.NONE, null);
    }

    public static InvocationContext none() {
        return new InvocationContext(null, null, null, "test", Caller.NONE, null);
    }

    public InvocationContext withCaller(Caller c) {
        return new InvocationContext(connection, elicitation, log, via, c, callerToken);
    }

    public InvocationContext withCaller(Caller c, String token) {
        return new InvocationContext(connection, elicitation, log, via, c, token);
    }

    /** Never prints the token. */
    @Override
    public String toString() {
        return "InvocationContext[via=" + via + ", caller=" + caller + ", token="
                + (callerToken == null ? "none" : "present") + "]";
    }

    public String connectionId() {
        return connection == null ? "-" : connection.id();
    }

    public String clientName() {
        if (connection == null || connection.initialRequest() == null
                || connection.initialRequest().implementation() == null) {
            return "-";
        }
        return connection.initialRequest().implementation().name();
    }
}
