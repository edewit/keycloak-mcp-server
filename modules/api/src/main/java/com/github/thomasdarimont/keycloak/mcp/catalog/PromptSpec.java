package com.github.thomasdarimont.keycloak.mcp.catalog;

import java.util.ArrayList;
import java.util.LinkedHashMap;
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
     * One argument of a prompt; made by {@link Builder#argument} and
     * {@link Builder#required}.
     *
     * @param name the argument's name, as the handler finds it in its map
     * @param description what to enter, shown by the client next to the field
     * @param required whether the client must pass a value; a call without one is refused
     * before the handler runs
     * @param defaultValue value used when the client passes none or a blank one;
     * {@code null} for none
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

    /**
     * The arguments as received plus the defaults of the missing ones, blank values left
     * out: what the handler gets.
     */
    public Map<String, String> withDefaults(Map<String, String> given) {
        Map<String, String> out = new LinkedHashMap<>();
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

    /**
     * A builder for a prompt; a {@code PromptProvider} returns the specs from
     * {@code prompts(ctx)}.
     *
     * @param name what clients list and request it by: snake_case, starting with
     * {@code keycloak_} like the built-in prompts ({@code keycloak_onboard_user}), unique
     * among all prompts
     */
    public static Builder builder(String name) {
        return new Builder(name);
    }

    /**
     * Declares one prompt; {@link #build()} makes the {@link PromptSpec}. Required: a
     * {@link #title}, a {@link #description} and a {@link #handler}; arguments and tools
     * are optional.
     * {@snippet :
     * PromptSpec.builder("keycloak_acme_offboard")
     *     .title("Offboard a leaver")
     *     .description("Disables a leaver's account, ends their sessions and removes their group memberships.")
     *     .required("username", "Username of the leaver")
     *     .argument("realm", "Realm of the account; the default realm if empty")
     *     .argument("ticket", "Change ticket", "none")
     *     .tools("keycloak_user_get", "keycloak_acme_user_offboard")
     *     .handler(a -> "Offboard " + a.get("username") + " (ticket " + a.get("ticket") + "). First read the"
     *             + " user back and confirm it is the right person, then offboard and report what changed.")
     *     .build();
     * }
     */
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

        /**
         * Short human readable name, e.g. {@code Onboard a new user}: what clients show
         * in their prompt picker. Required.
         */
        public Builder title(String title) {
            this.title = title;
            return this;
        }

        /**
         * What the recipe achieves, one or two sentences, shown by clients under the
         * title. The server appends the tools it uses ("Uses keycloak_user_create, ...").
         * Required.
         */
        public Builder description(String description) {
            this.description = description;
            return this;
        }

        /**
         * An optional argument. Every argument is a string; one the client leaves out or
         * blank is not in the handler's map. Prompts get no {@code realm} or
         * {@code system} argument of their own: declare one when the recipe should name
         * them, and let the handler say "the default realm" without it.
         *
         * @param description what to enter, shown by the client
         */
        public Builder argument(String name, String description) {
            arguments.add(new Argument(name, description, false, null));
            return this;
        }

        /**
         * An argument the client must pass: a request without it, or with a blank value,
         * is refused ({@code INVALID_PARAMS}) before the handler runs, so the handler can
         * rely on it.
         *
         * @param description what to enter, shown by the client
         */
        public Builder required(String name, String description) {
            arguments.add(new Argument(name, description, true, null));
            return this;
        }

        /**
         * An optional argument with a default: the handler gets {@code defaultValue} when
         * the client passes none or a blank one, and clients may show it.
         *
         * @param description what to enter, shown by the client
         */
        public Builder argument(String name, String description, String defaultValue) {
            arguments.add(new Argument(name, description, false, defaultValue));
            return this;
        }

        /**
         * The catalog tools the recipe uses, in the order it uses them. The server
         * appends them to the rendered text with their level, description and parameters,
         * so the model calls them by name instead of searching; in the
         * {@code progressive} exposure mode it also lists them for the connection. Names
         * resolve forgivingly (with or without {@code keycloak_}, any case). A tool that
         * does not exist is logged and left out, one the server's policy does not permit
         * is left out; a prompt none of whose tools is available is not offered at all.
         * Without tools the prompt is offered as it is.
         */
        public Builder tools(String... names) {
            tools.addAll(List.of(names));
            return this;
        }

        /**
         * Renders the recipe: gets the arguments (defaults applied, blank ones left out)
         * and returns the instructions for the model as plain text, sent as the user's
         * message. Write steps the model can follow and verify; the server adds the tool
         * list after it. Required.
         */
        public Builder handler(Function<Map<String, String>, String> handler) {
            this.handler = handler;
            return this;
        }

        /**
         * The spec.
         *
         * @throws NullPointerException when the title, description or handler is missing
         */
        public PromptSpec build() {
            return new PromptSpec(name, title, description, arguments, tools, handler);
        }

    }

}
