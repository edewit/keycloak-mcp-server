package com.github.thomasdarimont.keycloak.mcp.catalog;

import java.util.List;

import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

/**
 * Builder for the flat JSON schemas we expose to the model: one level of properties,
 * primitive types, enums, arrays of strings and string maps. No oneOf/anyOf, no nesting.
 */
public final class InputSchema {

    public static final String REALM = "realm";
    public static final String SYSTEM = "system";
    public static final String FIRST = "first";
    public static final String MAX = "max";
    public static final String CONFIRM = "confirm";

    private InputSchema() {
    }

    public static Builder builder() {
        return new Builder();
    }

    /** Adds (or replaces) the {@code realm} property as the first property. */
    public static JsonObject withRealm(JsonObject schema, boolean required, String defaultRealm) {
        JsonObject realm = new JsonObject().put("type", "string");
        String desc = "Realm name";
        if ("(per system)".equals(defaultRealm)) {
            desc += " (default: the system's default realm)";
        }
        else if (defaultRealm != null) {
            desc += " (default: " + defaultRealm + ")";
        }
        realm.put("description", desc);
        JsonObject props = new JsonObject();
        props.put(REALM, realm);
        JsonObject old = schema.getJsonObject("properties");
        if (old != null) {
            for (String k : old.fieldNames()) {
                if (!k.equals(REALM)) {
                    props.put(k, old.getValue(k));
                }
            }
        }
        JsonArray req = new JsonArray();
        if (required) {
            req.add(REALM);
        }
        JsonArray oldReq = schema.getJsonArray("required");
        if (oldReq != null) {
            for (Object o : oldReq) {
                if (!REALM.equals(o)) {
                    req.add(o);
                }
            }
        }
        JsonObject out = schema.copy();
        out.put("properties", props);
        if (req.isEmpty()) {
            out.remove("required");
        }
        else {
            out.put("required", req);
        }
        return out;
    }

    /**
     * Adds the {@code system} enum property in front of everything else (multi-system
     * deployments).
     */
    public static JsonObject withSystem(JsonObject schema, List<String> systems, String defaultSystem) {
        JsonObject prop = new JsonObject().put("type", "string").put("enum", new JsonArray(systems));
        prop.put("description",
                defaultSystem != null ? "Keycloak system (default: " + defaultSystem + ")" : "Keycloak system");
        JsonObject props = new JsonObject().put(SYSTEM, prop);
        JsonObject old = schema.getJsonObject("properties");
        if (old != null) {
            for (String k : old.fieldNames()) {
                if (!k.equals(SYSTEM)) {
                    props.put(k, old.getValue(k));
                }
            }
        }
        JsonArray req = new JsonArray();
        if (defaultSystem == null) {
            req.add(SYSTEM);
        }
        JsonArray oldReq = schema.getJsonArray("required");
        if (oldReq != null) {
            for (Object o : oldReq) {
                if (!SYSTEM.equals(o)) {
                    req.add(o);
                }
            }
        }
        JsonObject out = schema.copy();
        out.put("properties", props);
        if (req.isEmpty()) {
            out.remove("required");
        }
        else {
            out.put("required", req);
        }
        return out;
    }

    /** Sets the maximum of the {@code max} pagination property, if present. */
    public static JsonObject withMaxItems(JsonObject schema, int maxItems) {
        JsonObject props = schema.getJsonObject("properties");
        if (props == null || props.getJsonObject(MAX) == null) {
            return schema;
        }
        JsonObject out = schema.copy();
        JsonObject max = out.getJsonObject("properties").getJsonObject(MAX);
        max.put("maximum", maxItems);
        if (max.getInteger("default", 0) > maxItems) {
            max.put("default", maxItems);
        }
        return out;
    }

    public static final class Builder {
        private final JsonObject properties = new JsonObject();
        private final JsonArray required = new JsonArray();
        private JsonObject current;

        private Builder() {
        }

        private Builder add(String name, String type, String description) {
            current = new JsonObject().put("type", type);
            if (description != null && !description.isBlank()) {
                current.put("description", description);
            }
            properties.put(name, current);
            return this;
        }

        public Builder string(String name, String description) {
            return add(name, "string", description);
        }

        public Builder integer(String name, String description) {
            return add(name, "integer", description);
        }

        public Builder number(String name, String description) {
            return add(name, "number", description);
        }

        public Builder bool(String name, String description) {
            return add(name, "boolean", description);
        }

        public Builder enumeration(String name, String description, String... values) {
            add(name, "string", description);
            current.put("enum", new JsonArray(List.of(values)));
            return this;
        }

        public Builder stringArray(String name, String description) {
            add(name, "array", description);
            current.put("items", new JsonObject().put("type", "string"));
            return this;
        }

        /**
         * Object with arbitrary string values, e.g. provider config or user attributes.
         */
        public Builder stringMap(String name, String description) {
            add(name, "object", description);
            current.put("additionalProperties", new JsonObject().put("type", "string"));
            return this;
        }

        /**
         * Object with arbitrary values (used sparingly, e.g. for realm update patches).
         */
        public Builder anyMap(String name, String description) {
            add(name, "object", description);
            current.put("additionalProperties", true);
            return this;
        }

        /** Marks the most recently added property as required. */
        public Builder required() {
            String last = null;
            for (String k : properties.fieldNames()) {
                last = k;
            }
            if (last != null && !required.contains(last)) {
                required.add(last);
            }
            return this;
        }

        public Builder def(Object defaultValue) {
            current.put("default", defaultValue);
            return this;
        }

        public Builder min(int minimum) {
            current.put("minimum", minimum);
            return this;
        }

        public Builder max(int maximum) {
            current.put("maximum", maximum);
            return this;
        }

        /** Standard {@code first} / {@code max} pagination parameters. */
        public Builder pagination() {
            integer(FIRST, "Pagination offset").min(0).def(0);
            integer(MAX, "Max results to return").min(1).def(20);
            return this;
        }

        public JsonObject build() {
            JsonObject schema = new JsonObject().put("type", "object").put("properties", properties.copy());
            if (!required.isEmpty()) {
                schema.put("required", required.copy());
            }
            return schema;
        }
    }
}
