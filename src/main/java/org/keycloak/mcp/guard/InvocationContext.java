package org.keycloak.mcp.guard;

import io.quarkiverse.mcp.server.Elicitation;
import io.quarkiverse.mcp.server.McpConnection;
import io.quarkiverse.mcp.server.McpLog;
import io.quarkiverse.mcp.server.ToolManager.ToolArguments;

/**
 * What the invoker needs from the transport layer. Decoupled from {@link ToolArguments} so unit tests can fake it.
 *
 * @param via "direct" or "execute_tool", for the audit log
 */
public record InvocationContext(McpConnection connection, Elicitation elicitation, McpLog log, String via) {

    public static InvocationContext of(ToolArguments args, String via) {
        return new InvocationContext(args.connection(), args.elicitation(), args.log(), via);
    }

    public static InvocationContext none() {
        return new InvocationContext(null, null, null, "test");
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
