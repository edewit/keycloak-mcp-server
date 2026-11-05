package com.github.thomasdarimont.keycloak.mcp.catalog;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;

/**
 * A reusable task recipe the user can pick in their MCP client ({@code prompts/list}).
 * The handler renders the instructions for the given arguments; the server appends the
 * exact tools named in {@link #tools()} with their parameters, so the model can call them
 * directly instead of searching, and in progressive exposure mode lists them.
 *
 * @param name unique prompt name, e.g. {@code keycloak_onboard_user}
 * @param title short human readable title shown by clients
 * @param description what the recipe achieves; one or two sentences
 * @param arguments the prompt's arguments, all strings
 * @param tools names of the catalog tools the recipe relies on, in the order they are
 * used
 * @param handler renders the recipe text for the arguments (defaults already applied)
 */
public record PromptSpec(String name, String title, String description, List<Argument> arguments, List<String> tools,
        Function<Map<String, String>, String> handler) {

    /**
     * @param defaultValue value used when the client passes none; {@code null} for none
     */
    public record Argument(String name, String description, boolean required, String defaultValue) {
    }

    public PromptSpec {
        Objects.requireNonNull(name, "name");
        Objects.requireNonNull(title, "title");
        Objects.requireNonNull(description, "description");
        Objects.requireNonNull(handler, "handler");
        arguments = List.copyOf(arguments == null ? List.of() : arguments);
        tools = List.copyOf(tools == null ? List.of() : tools);
    }

    /** Arguments as received plus the defaults of the missing ones. */
    public Map<String, String> withDefaults(Map<String, String> given) {
        Map<String, String> out = new java.util.LinkedHashMap<>();
        for (Argument a : arguments) {
            String v = given == null ? null : given.get(a.name());
            if ((v == null || v.isBlank()) && a.defaultValue() != null) {
                v = a.defaultValue();
            }
            if (v != null && !v.isBlank()) {
                out.put(a.name(), v);
            }
        }
        return out;
    }

    public static Builder builder(String name) {
        return new Builder(name);
    }

    public static final class Builder {

        private final String name;

        private String title;

        private String description;

        private final List<Argument> arguments = new ArrayList<>();

        private final List<String> tools = new ArrayList<>();

        private Function<Map<String, String>, String> handler;

        private Builder(String name) {
            this.name = name;
        }

        public Builder title(String title) {
            this.title = title;
            return this;
        }

        public Builder description(String description) {
            this.description = description;
            return this;
        }

        public Builder argument(String name, String description) {
            arguments.add(new Argument(name, description, false, null));
            return this;
        }

        public Builder required(String name, String description) {
            arguments.add(new Argument(name, description, true, null));
            return this;
        }

        public Builder argument(String name, String description, String defaultValue) {
            arguments.add(new Argument(name, description, false, defaultValue));
            return this;
        }

        /** Catalog tools the recipe uses; they are appended to the rendered prompt. */
        public Builder tools(String... names) {
            tools.addAll(List.of(names));
            return this;
        }

        public Builder handler(Function<Map<String, String>, String> handler) {
            this.handler = handler;
            return this;
        }

        public PromptSpec build() {
            return new PromptSpec(name, title, description, arguments, tools, handler);
        }

    }

}
