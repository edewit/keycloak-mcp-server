package com.github.thomasdarimont.keycloak.mcp.authzen;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

/**
 * A PDP's answer to an evaluation: its {@code decision}, its {@code context}, and every
 * further top-level field ({@link #attributes()}: a PDP's extensions, later additions to
 * the API) as plain maps, lists and values.
 *
 * @param decision {@code true}: allowed
 * @param context the answer's context; empty when it has none
 * @param attributes the other top-level fields
 */
public record AuthZenAnswer(boolean decision, JsonObject context, Map<String, Object> attributes) {

    /** Response context key a PDP sets to hand an allowed call to the human. */
    public static final String CONFIRMATION_REQUIRED = "confirmation_required";

    public AuthZenAnswer {
        context = context == null ? new JsonObject() : context.copy();
        attributes = attributes == null ? Map.of() : Collections.unmodifiableMap(new LinkedHashMap<>(attributes));
    }

    @Override
    public JsonObject context() {
        return context.copy();
    }

    /**
     * Reads an answer.
     *
     * @throws IllegalArgumentException without a boolean {@code decision}
     */
    public static AuthZenAnswer parse(JsonObject json) {
        if (json == null || !(json.getValue("decision") instanceof Boolean decision)) {
            throw new IllegalArgumentException("the PDP's answer has no boolean decision");
        }
        JsonObject context = json.getValue("context") instanceof JsonObject c ? c : new JsonObject();
        Map<String, Object> attributes = new LinkedHashMap<>();
        for (String field : json.fieldNames()) {
            if (!"decision".equals(field) && !"context".equals(field)) {
                attributes.put(field, plain(json.getValue(field)));
            }
        }
        return new AuthZenAnswer(decision, context, attributes);
    }

    /** Whether an allowed call needs the human's own confirmation. */
    public boolean confirmationRequired() {
        return decision && context.getValue(CONFIRMATION_REQUIRED) instanceof Boolean b && b;
    }

    /**
     * Why: {@code reason_user}, else {@code reason_admin}, else {@code reason}; a string
     * or, as in the AuthZEN examples, texts by language ({@code en} preferred).
     */
    public Optional<String> reason() {
        for (String key : List.of("reason_user", "reason_admin", "reason")) {
            Object v = context.getValue(key);
            if (v instanceof String s && !s.isBlank()) {
                return Optional.of(s);
            }
            if (v instanceof JsonObject texts && !texts.isEmpty()) {
                Object en = texts.getValue("en");
                Object any = en != null ? en : texts.getValue(texts.fieldNames().iterator().next());
                if (any instanceof String s && !s.isBlank()) {
                    return Optional.of(s);
                }
            }
        }
        return Optional.empty();
    }

    /** Vert.x JSON containers as the plain maps and lists they wrap, all the way down. */
    static Object plain(Object value) {
        if (value instanceof JsonObject o) {
            Map<String, Object> out = new LinkedHashMap<>();
            o.forEach(e -> out.put(e.getKey(), plain(e.getValue())));
            return Collections.unmodifiableMap(out);
        }
        if (value instanceof JsonArray a) {
            List<Object> out = new ArrayList<>();
            a.forEach(v -> out.add(plain(v)));
            return Collections.unmodifiableList(out);
        }
        return value;
    }
}
