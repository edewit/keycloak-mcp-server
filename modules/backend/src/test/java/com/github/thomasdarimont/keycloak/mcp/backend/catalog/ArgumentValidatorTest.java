package com.github.thomasdarimont.keycloak.mcp.backend.catalog;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import com.github.thomasdarimont.keycloak.mcp.catalog.InputSchema;

import io.vertx.core.json.JsonObject;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ArgumentValidatorTest {

    private final JsonObject schema = InputSchema.builder()
        .string("id", "id")
        .required()
        .bool("enabled", "flag")
        .integer("count", "n")
        .min(0)
        .max(10)
        .def(3)
        .enumeration("action", "a", "full", "changed")
        .stringArray("uris", "list")
        .stringMap("config", "map")
        .build();

    @Test
    void appliesDefaultsAndDropsUnknown() {
        var out = ArgumentValidator.validate(schema, Map.of("id", "x", "bogus", 1));
        assertTrue(out.valid());
        assertEquals(Map.of("id", "x", "count", 3), out.values());
    }

    @Test
    void reportsMissingRequired() {
        var out = ArgumentValidator.validate(schema, Map.of());
        assertFalse(out.valid());
        assertEquals("id", out.problems().get(0).field());
        assertEquals("is required", out.problems().get(0).message());
    }

    @Test
    void coercesSloppyValues() {
        Map<String, Object> raw = new HashMap<>();
        raw.put("id", 42);
        raw.put("enabled", "true");
        raw.put("count", "7");
        raw.put("action", "FULL");
        raw.put("uris", "a, b");
        raw.put("config", new JsonObject().put("k", 1));
        var out = ArgumentValidator.validate(schema, raw);
        assertTrue(out.valid(), out.problems().toString());
        assertEquals("42", out.values().get("id"));
        assertEquals(Boolean.TRUE, out.values().get("enabled"));
        assertEquals(7, out.values().get("count"));
        assertEquals("full", out.values().get("action"));
        assertEquals(List.of("a", "b"), out.values().get("uris"));
        assertEquals(Map.of("k", "1"), out.values().get("config"));
    }

    @Test
    void clampsAboveMaximumButRejectsBelowMinimum() {
        assertEquals(10, ArgumentValidator.validate(schema, Map.of("id", "x", "count", 500)).values().get("count"));
        var out = ArgumentValidator.validate(schema, Map.of("id", "x", "count", -1));
        assertFalse(out.valid());
        assertEquals("count", out.problems().get(0).field());
    }

    @Test
    void rejectsBadEnumAndTypes() {
        var out = ArgumentValidator.validate(schema,
                Map.of("id", "x", "action", "nope", "enabled", "maybe", "count", 1.5));
        assertFalse(out.valid());
        assertEquals(List.of("enabled", "count", "action"),
                out.problems().stream().map(ArgumentValidator.Problem::field).toList());
        assertEquals("one of [\"full\",\"changed\"]", out.problems().get(2).expected());
    }

    @Test
    void nullMeansMissing() {
        Map<String, Object> raw = new HashMap<>();
        raw.put("id", "x");
        raw.put("enabled", null);
        var out = ArgumentValidator.validate(schema, raw);
        assertTrue(out.valid());
        assertNull(out.values().get("enabled"));
    }
}
