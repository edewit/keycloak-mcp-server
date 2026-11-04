package com.github.thomasdarimont.keycloak.mcp.server.catalog;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import com.github.thomasdarimont.keycloak.mcp.catalog.InputSchema;

import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

/**
 * Hand-rolled validator for the flat schemas produced by {@link InputSchema}. Besides
 * checking it also coerces the sloppy values small models produce ("true" -> true, "5" ->
 * 5, 5.0 -> 5, "a,b" -> ["a","b"]) and applies defaults.
 */
public final class ArgumentValidator {

    public record Problem(String field, String message, String expected) {
        public Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("field", field);
            m.put("message", message);
            if (expected != null) {
                m.put("expected", expected);
            }
            return m;
        }
    }

    public record Outcome(Map<String, Object> values, List<Problem> problems) {
        public boolean valid() {
            return problems.isEmpty();
        }
    }

    private ArgumentValidator() {
    }

    public static Outcome validate(JsonObject schema, Map<String, Object> raw) {
        Map<String, Object> in = raw == null ? Map.of() : raw;
        Map<String, Object> out = new LinkedHashMap<>();
        List<Problem> problems = new ArrayList<>();
        JsonObject props = schema.getJsonObject("properties", new JsonObject());
        JsonArray required = schema.getJsonArray("required", new JsonArray());

        for (String name : props.fieldNames()) {
            JsonObject prop = props.getJsonObject(name);
            Object value = in.get(name);
            if (value == null && in.containsKey(name)) {
                value = null; // explicit null == missing
            }
            if (value == null) {
                if (required.contains(name)) {
                    problems.add(new Problem(name, "is required", describe(prop)));
                }
                else if (prop.containsKey("default")) {
                    out.put(name, prop.getValue("default"));
                }
                continue;
            }
            Object coerced = coerce(name, prop, value, problems);
            if (coerced != null) {
                out.put(name, coerced);
            }
        }
        return new Outcome(out, problems);
    }

    private static Object coerce(String name, JsonObject prop, Object value, List<Problem> problems) {
        String type = prop.getString("type", "string");
        switch (type) {
            case "string" -> {
                String s;
                if (value instanceof String str) {
                    s = str;
                }
                else if (value instanceof Number || value instanceof Boolean) {
                    s = String.valueOf(value);
                }
                else {
                    problems.add(new Problem(name, "must be a string", describe(prop)));
                    return null;
                }
                JsonArray allowed = prop.getJsonArray("enum");
                if (allowed != null && !allowed.contains(s)) {
                    // case-insensitive rescue
                    String match = null;
                    for (Object o : allowed) {
                        if (o.toString().equalsIgnoreCase(s.trim())) {
                            match = o.toString();
                        }
                    }
                    if (match == null) {
                        problems.add(new Problem(name, "must be one of " + allowed.encode(), describe(prop)));
                        return null;
                    }
                    s = match;
                }
                return s;
            }
            case "integer" -> {
                Long l = toLong(value);
                if (l == null) {
                    problems.add(new Problem(name, "must be an integer", describe(prop)));
                    return null;
                }
                Integer min = prop.getInteger("minimum");
                Integer max = prop.getInteger("maximum");
                if (min != null && l < min) {
                    problems.add(new Problem(name, "must be >= " + min, describe(prop)));
                    return null;
                }
                if (max != null && l > max) {
                    // clamp instead of failing; models love max=1000
                    l = max.longValue();
                }
                return l >= Integer.MIN_VALUE && l <= Integer.MAX_VALUE ? (Object) l.intValue() : l;
            }
            case "number" -> {
                Double d = toDouble(value);
                if (d == null) {
                    problems.add(new Problem(name, "must be a number", describe(prop)));
                    return null;
                }
                return d;
            }
            case "boolean" -> {
                if (value instanceof Boolean b) {
                    return b;
                }
                if (value instanceof String s) {
                    String t = s.trim().toLowerCase(Locale.ROOT);
                    if (t.equals("true") || t.equals("yes") || t.equals("1")) {
                        return Boolean.TRUE;
                    }
                    if (t.equals("false") || t.equals("no") || t.equals("0")) {
                        return Boolean.FALSE;
                    }
                }
                if (value instanceof Number n) {
                    return n.intValue() != 0;
                }
                problems.add(new Problem(name, "must be true or false", describe(prop)));
                return null;
            }
            case "array" -> {
                List<String> items = new ArrayList<>();
                if (value instanceof JsonArray ja) {
                    value = ja.getList();
                }
                if (value instanceof List<?> list) {
                    for (Object o : list) {
                        if (o != null) {
                            items.add(String.valueOf(o));
                        }
                    }
                }
                else if (value instanceof String s) {
                    String t = s.trim();
                    if (t.startsWith("[") && t.endsWith("]")) {
                        try {
                            for (Object o : new JsonArray(t)) {
                                items.add(String.valueOf(o));
                            }
                        }
                        catch (RuntimeException e) {
                            problems.add(new Problem(name, "must be an array of strings", describe(prop)));
                            return null;
                        }
                    }
                    else if (!t.isEmpty()) {
                        for (String part : t.split(",")) {
                            if (!part.isBlank()) {
                                items.add(part.trim());
                            }
                        }
                    }
                }
                else {
                    problems.add(new Problem(name, "must be an array of strings", describe(prop)));
                    return null;
                }
                return items;
            }
            case "object" -> {
                Map<String, Object> map;
                if (value instanceof JsonObject jo) {
                    map = jo.getMap();
                }
                else if (value instanceof Map<?, ?> m) {
                    map = new LinkedHashMap<>();
                    for (Map.Entry<?, ?> e : m.entrySet()) {
                        map.put(String.valueOf(e.getKey()), e.getValue());
                    }
                }
                else if (value instanceof String s && s.trim().startsWith("{")) {
                    try {
                        map = new JsonObject(s).getMap();
                    }
                    catch (RuntimeException e) {
                        problems.add(new Problem(name, "must be an object", describe(prop)));
                        return null;
                    }
                }
                else {
                    problems.add(new Problem(name, "must be an object", describe(prop)));
                    return null;
                }
                Object additional = prop.getValue("additionalProperties");
                if (additional instanceof JsonObject ap && "string".equals(ap.getString("type"))) {
                    Map<String, Object> strings = new LinkedHashMap<>();
                    for (Map.Entry<String, Object> e : map.entrySet()) {
                        if (e.getValue() != null) {
                            strings.put(e.getKey(), String.valueOf(e.getValue()));
                        }
                    }
                    return strings;
                }
                return map;
            }
            default -> {
                return value;
            }
        }
    }

    private static Long toLong(Object value) {
        if (value instanceof Integer || value instanceof Long || value instanceof Short || value instanceof Byte) {
            return ((Number) value).longValue();
        }
        if (value instanceof Number n) {
            double d = n.doubleValue();
            return d == Math.rint(d) ? (Long) (long) d : null;
        }
        if (value instanceof String s) {
            try {
                return Long.parseLong(s.trim());
            }
            catch (NumberFormatException e) {
                Double d = toDouble(s);
                return d != null && d == Math.rint(d) ? (Long) d.longValue() : null;
            }
        }
        return null;
    }

    private static Double toDouble(Object value) {
        if (value instanceof Number n) {
            return n.doubleValue();
        }
        if (value instanceof String s) {
            try {
                return Double.parseDouble(s.trim());
            }
            catch (NumberFormatException e) {
                return null;
            }
        }
        return null;
    }

    /** Short human readable type description for error messages. */
    static String describe(JsonObject prop) {
        String type = prop.getString("type", "string");
        JsonArray en = prop.getJsonArray("enum");
        if (en != null) {
            return "one of " + en.encode();
        }
        return switch (type) {
            case "array" -> "array of strings";
            case "object" -> "object";
            default -> type;
        };
    }
}
