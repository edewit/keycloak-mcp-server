package org.keycloak.mcp.catalog;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import io.vertx.core.json.JsonObject;

/**
 * Catalog entry for one tool. See implementation-plan.md §3.
 *
 * @param inputSchema flat JSON schema of the tool's own parameters; the catalog adds {@code realm} for realm scoped
 *                    tools and clamps pagination
 * @param synonyms    extra search terms, never shown to the model
 * @param hot         candidate for direct exposure in hybrid mode
 * @param realmScoped whether the tool takes a {@code realm} argument
 */
public record ToolSpec(
        String name,
        String title,
        String description,
        Category category,
        ToolLevel level,
        boolean idempotent,
        JsonObject inputSchema,
        List<String> synonyms,
        boolean hot,
        boolean realmScoped,
        ToolHandler handler) {

    public ToolSpec {
        Objects.requireNonNull(name, "name");
        Objects.requireNonNull(title, "title");
        Objects.requireNonNull(description, "description");
        Objects.requireNonNull(category, "category");
        Objects.requireNonNull(level, "level");
        Objects.requireNonNull(handler, "handler");
        inputSchema = inputSchema == null ? InputSchema.builder().build() : inputSchema;
        synonyms = List.copyOf(synonyms == null ? List.of() : synonyms);
    }

    public boolean isDestructive() {
        return level == ToolLevel.DESTRUCTIVE;
    }

    public boolean isReadOnly() {
        return level == ToolLevel.READ;
    }

    public ToolSpec withInputSchema(JsonObject schema) {
        return new ToolSpec(name, title, description, category, level, idempotent, schema, synonyms, hot, realmScoped,
                handler);
    }

    public ToolSpec withHot(boolean hotFlag) {
        return new ToolSpec(name, title, description, category, level, idempotent, inputSchema, synonyms, hotFlag,
                realmScoped, handler);
    }

    /** Parameter names declared in the (effective) schema, in declaration order. */
    public List<String> parameterNames() {
        JsonObject props = inputSchema.getJsonObject("properties");
        return props == null ? List.of() : new ArrayList<>(props.fieldNames());
    }

    public static Builder builder(String name) {
        return new Builder(name);
    }

    public static final class Builder {
        private final String name;
        private String title;
        private String description;
        private Category category;
        private ToolLevel level = ToolLevel.READ;
        private Boolean idempotent;
        private JsonObject inputSchema;
        private final List<String> synonyms = new ArrayList<>();
        private boolean hot;
        private boolean realmScoped = true;
        private ToolHandler handler;

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

        public Builder category(Category category) {
            this.category = category;
            return this;
        }

        public Builder read() {
            this.level = ToolLevel.READ;
            return this;
        }

        public Builder write() {
            this.level = ToolLevel.WRITE;
            return this;
        }

        public Builder destructive() {
            this.level = ToolLevel.DESTRUCTIVE;
            return this;
        }

        public Builder idempotent(boolean idempotent) {
            this.idempotent = idempotent;
            return this;
        }

        public Builder schema(InputSchema.Builder schema) {
            this.inputSchema = schema.build();
            return this;
        }

        public Builder synonyms(String... terms) {
            synonyms.addAll(List.of(terms));
            return this;
        }

        public Builder hot() {
            this.hot = true;
            return this;
        }

        /** Tool does not take a realm argument (e.g. server info). */
        public Builder global() {
            this.realmScoped = false;
            return this;
        }

        public Builder handler(ToolHandler handler) {
            this.handler = handler;
            return this;
        }

        public ToolSpec build() {
            boolean idem = idempotent != null ? idempotent : level == ToolLevel.READ;
            return new ToolSpec(name, title, description, category, level, idem, inputSchema, synonyms, hot, realmScoped,
                    handler);
        }
    }
}
