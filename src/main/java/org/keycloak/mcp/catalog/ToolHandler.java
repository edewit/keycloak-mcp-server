package org.keycloak.mcp.catalog;

@FunctionalInterface
public interface ToolHandler {

    /**
     * Executes the tool. Arguments in {@code call} are already validated and coerced against the spec schema,
     * the realm (if any) is resolved and allowed.
     *
     * @throws Exception any failure; the invoker maps it to a structured error result
     */
    ToolResult handle(ToolCall call) throws Exception;
}
