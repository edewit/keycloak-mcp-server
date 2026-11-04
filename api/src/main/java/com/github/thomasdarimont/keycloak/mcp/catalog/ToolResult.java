package com.github.thomasdarimont.keycloak.mcp.catalog;

import java.util.LinkedHashMap;
import java.util.Map;

import io.vertx.core.json.Json;

/**
 * Outcome of a tool execution. {@code payload} is serialised to compact JSON text.
 */
public record ToolResult(boolean isError, Object payload) {

    public static ToolResult ok(Object payload) {
        return new ToolResult(false, payload);
    }

    /**
     * Short confirmation for write operations: {@code {"ok":true,"message":...}} plus
     * extra fields.
     */
    public static ToolResult done(String message, Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("ok", true);
        m.put("message", message);
        for (int i = 0; i + 1 < kv.length; i += 2) {
            m.put(String.valueOf(kv[i]), kv[i + 1]);
        }
        return new ToolResult(false, m);
    }

    public static ToolResult error(String code, String message, Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("error", code);
        if (message != null) {
            m.put("message", message);
        }
        for (int i = 0; i + 1 < kv.length; i += 2) {
            if (kv[i + 1] != null) {
                m.put(String.valueOf(kv[i]), kv[i + 1]);
            }
        }
        return new ToolResult(true, m);
    }

    public String toJson() {
        return payload instanceof String s ? s : Json.encode(payload);
    }
}
