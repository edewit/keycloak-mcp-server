package com.github.thomasdarimont.keycloak.mcp.conformance;

import java.util.List;

import com.github.thomasdarimont.keycloak.mcp.catalog.PromptSpec;
import com.github.thomasdarimont.keycloak.mcp.prompts.PromptProvider;
import com.github.thomasdarimont.keycloak.mcp.spi.ExtensionContext;
import com.google.auto.service.AutoService;

/**
 * The {@code test_*} prompts the MCP conformance suite fetches, with the texts it
 * expects.
 */
@AutoService(PromptProvider.class)
public class ConformancePrompts implements PromptProvider {

    @Override
    public String id() {
        return "conformance-prompts";
    }

    @Override
    public List<PromptSpec> prompts(ExtensionContext context) {
        return List.of(
                PromptSpec.builder("test_simple_prompt")
                    .title("Conformance: simple prompt")
                    .description("A fixed text (MCP conformance suite).")
                    .handler(a -> "This is a simple prompt for testing.")
                    .build(),
                PromptSpec.builder("test_prompt_with_arguments")
                    .title("Conformance: prompt with arguments")
                    .description("Echoes its two arguments (MCP conformance suite).")
                    .required("arg1", "First test argument")
                    .required("arg2", "Second test argument")
                    .handler(a -> "Prompt with arguments: arg1='" + a.get("arg1") + "', arg2='" + a.get("arg2") + "'")
                    .build());
    }
}
