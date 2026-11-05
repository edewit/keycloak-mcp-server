package com.github.thomasdarimont.keycloak.mcp.backend.meta;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import com.github.thomasdarimont.keycloak.mcp.catalog.ToolResult;

import io.quarkiverse.mcp.server.TextContent;
import io.quarkiverse.mcp.server.ToolResponse;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class StructuredContentTest {

    @Test
    void objectPayloadsAreMirrored() {
        ToolResponse r = McpToolRegistrar.toResponse(ToolResult.ok(Map.of("a", 1)), true);
        assertEquals(Map.of("a", 1), r.structuredContent());
        assertEquals("{\"a\":1}", ((TextContent) r.firstContent()).text());
    }

    @Test
    void listsAreWrappedAndStringsSkipped() {
        assertEquals(Map.of("items", List.of(1, 2)),
                McpToolRegistrar.toResponse(ToolResult.ok(List.of(1, 2)), true).structuredContent());
        assertNull(McpToolRegistrar.toResponse(ToolResult.ok("plain"), true).structuredContent());
    }

    @Test
    void errorsKeepTheirCodeAndTheSwitchTurnsItOff() {
        ToolResponse err = McpToolRegistrar.toResponse(ToolResult.error("nope", "No."), true);
        assertTrue(err.isError());
        assertEquals("nope", ((Map<?, ?>) err.structuredContent()).get("error"));
        assertNull(McpToolRegistrar.toResponse(ToolResult.ok(Map.of("a", 1)), false).structuredContent());
    }

}
