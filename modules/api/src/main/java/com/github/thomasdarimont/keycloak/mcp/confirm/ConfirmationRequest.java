package com.github.thomasdarimont.keycloak.mcp.confirm;

import java.util.Map;

import com.github.thomasdarimont.keycloak.mcp.access.Caller;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolSpec;

/**
 * What a {@link Confirmer} decides on: one destructive tool call about to run.
 *
 * @param tool the destructive tool about to run
 * @param system Keycloak system name, or {@code null} for the single system
 * @param realm target realm, or {@code null} for global tools
 * @param args validated arguments
 * @param confirmFlag whether the call carried {@code confirm: true}
 * @param caller who is acting; {@link Caller#NONE} on anonymous connections
 * @param prompter a way to ask the human through the MCP client, when it supports
 * elicitation
 * @param clientName the MCP client's name from {@code initialize} (LM Studio, Claude,
 * ...), or {@code null}: the requester a confirmer may show on the user's device
 */
public record ConfirmationRequest(ToolSpec tool, String system, String realm, Map<String, Object> args,
        boolean confirmFlag, Caller caller, Prompter prompter, String clientName) {

    public ConfirmationRequest {
        args = Map.copyOf(args == null ? Map.of() : args);
        caller = caller == null ? Caller.NONE : caller;
        prompter = prompter == null ? Prompter.NONE : prompter;
        clientName = clientName == null || clientName.isBlank() || clientName.equals("-") ? null : clientName;
    }

    public ConfirmationRequest(ToolSpec tool, String system, String realm, Map<String, Object> args,
            boolean confirmFlag, Caller caller, Prompter prompter) {
        this(tool, system, realm, args, confirmFlag, caller, prompter, null);
    }
}
