package com.github.thomasdarimont.keycloak.mcp.conformance;

import java.util.List;

import com.github.thomasdarimont.keycloak.mcp.catalog.Category;
import com.github.thomasdarimont.keycloak.mcp.catalog.InputSchema;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolResult;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolSpec;
import com.github.thomasdarimont.keycloak.mcp.tools.ToolProvider;
import com.github.thomasdarimont.keycloak.mcp.tools.ToolProviderContext;
import com.google.auto.service.AutoService;

/**
 * The {@code test_*} tools the MCP conformance suite calls, with the exact responses it
 * expects. Only the ones this server's tool model can express: text results and error
 * results. Image, audio and embedded-resource content, log and progress notifications,
 * sampling and elicitation from inside a tool are not part of the Keycloak tools and stay
 * in the expected-failures baseline.
 */
@AutoService(ToolProvider.class)
public class ConformanceToolProvider implements ToolProvider {

    @Override
    public String id() {
        return "conformance";
    }

    @Override
    public String displayName() {
        return "MCP conformance fixtures";
    }

    @Override
    public String description() {
        return "test_* tools of the MCP conformance suite; never ship this jar";
    }

    @Override
    public List<ToolSpec> tools(ToolProviderContext context) {
        return List.of(
                ToolSpec.builder("test_simple_text")
                    .title("Conformance: simple text")
                    .description("Returns a fixed text (MCP conformance suite).")
                    .category(Category.REALM)
                    .read()
                    .global()
                    .schema(InputSchema.builder())
                    .handler(call -> ToolResult.ok("This is a simple text response for testing."))
                    .build(),
                ToolSpec.builder("test_error_handling")
                    .title("Conformance: error")
                    .description("Always fails (MCP conformance suite).")
                    .category(Category.REALM)
                    .read()
                    .global()
                    .schema(InputSchema.builder())
                    .handler(call -> new ToolResult(true, "This tool intentionally returns an error for testing"))
                    .build());
    }
}
