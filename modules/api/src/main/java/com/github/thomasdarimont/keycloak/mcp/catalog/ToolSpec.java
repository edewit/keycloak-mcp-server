package com.github.thomasdarimont.keycloak.mcp.catalog;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

import com.github.thomasdarimont.keycloak.mcp.access.AccessCheck;
import com.github.thomasdarimont.keycloak.mcp.access.Delegation;

import io.vertx.core.json.JsonObject;

/**
 * Catalog entry for one tool. See implementation-plan.md §3.
 *
 * @param inputSchema flat JSON schema of the tool's own parameters; the catalog adds
 * {@code realm} for realm scoped tools and clamps pagination
 * @param synonyms extra search terms, never shown to the model
 * @param hot candidate for direct exposure in hybrid mode
 * @param realmScoped whether the tool takes a {@code realm} argument
 * @param api Admin REST operations the tool relies on (checked against the OpenAPI
 * document in tests)
 * @param requires features or versions the Keycloak system must have
 * @param requiredRoles {@code realm-management} roles the caller needs (any one of them
 * suffices per entry group, see
 * {@link com.github.thomasdarimont.keycloak.mcp.access.GrantedRoles}); empty = no realm
 * role needed
 * @param accessChecks extra per-call predicates, evaluated after roles and before
 * confirmation
 * @param delegation whether the tool may run under delegated access
 * @param sensitiveResult the result carries a secret (a client secret, a generated
 * password): it still goes to the caller, who asked for it, but the audit event says so
 * and nothing the server logs itself contains it
 */
public record ToolSpec(String name, String title, String description, Category category, ToolLevel level,
        boolean idempotent, JsonObject inputSchema, List<String> synonyms, boolean hot, boolean realmScoped,
        List<ApiOperation> api, Set<String> requiredRoles, List<Requirement> requires, List<AccessCheck> accessChecks,
        Delegation delegation, ToolHandler handler, boolean sensitiveResult) {

    public ToolSpec {
        Objects.requireNonNull(name, "name");
        Objects.requireNonNull(title, "title");
        Objects.requireNonNull(description, "description");
        Objects.requireNonNull(category, "category");
        Objects.requireNonNull(level, "level");
        Objects.requireNonNull(handler, "handler");
        inputSchema = inputSchema == null ? InputSchema.builder().build() : inputSchema;
        synonyms = List.copyOf(synonyms == null ? List.of() : synonyms);
        api = List.copyOf(api == null ? List.of() : api);
        requiredRoles = Set.copyOf(requiredRoles == null ? Set.of() : requiredRoles);
        requires = List.copyOf(requires == null ? List.of() : requires);
        accessChecks = List.copyOf(accessChecks == null ? List.of() : accessChecks);
        delegation = delegation == null ? Delegation.ALLOWED : delegation;
    }

    public boolean isDestructive() {
        return level == ToolLevel.DESTRUCTIVE;
    }

    public boolean isReadOnly() {
        return level == ToolLevel.READ;
    }

    public ToolSpec withInputSchema(JsonObject schema) {
        return new ToolSpec(name, title, description, category, level, idempotent, schema, synonyms, hot, realmScoped,
                api, requiredRoles, requires, accessChecks, delegation, handler, sensitiveResult);
    }

    public ToolSpec withName(String newName) {
        if (newName.equals(name)) {
            return this;
        }
        return new ToolSpec(newName, title, description, category, level, idempotent, inputSchema, synonyms, hot,
                realmScoped, api, requiredRoles, requires, accessChecks, delegation, handler, sensitiveResult);
    }

    public ToolSpec withHot(boolean hotFlag) {
        return new ToolSpec(name, title, description, category, level, idempotent, inputSchema, synonyms, hotFlag,
                realmScoped, api, requiredRoles, requires, accessChecks, delegation, handler, sensitiveResult);
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
        private ToolLevel level;
        private Boolean idempotent;
        private JsonObject inputSchema;
        private final List<String> synonyms = new ArrayList<>();
        private boolean hot;
        private boolean realmScoped = true;
        private final List<ApiOperation> api = new ArrayList<>();
        private final Set<String> requiredRoles = new LinkedHashSet<>();
        private final List<Requirement> requires = new ArrayList<>();
        private final List<AccessCheck> accessChecks = new ArrayList<>();
        private Delegation delegation = Delegation.ALLOWED;
        private ToolHandler handler;
        private boolean sensitiveResult;

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

        /** Admin REST operations this tool uses; see {@link ApiOperation}. */
        public Builder api(ApiOperation... operations) {
            api.addAll(List.of(operations));
            return this;
        }

        /**
         * {@code realm-management} roles needed in the target realm, e.g.
         * {@code roles("manage-users")}.
         */
        public Builder roles(String... roles) {
            requiredRoles.addAll(List.of(roles));
            return this;
        }

        /**
         * Keycloak features the system must have enabled, by CLI name
         * ({@code organization}, {@code passkeys}). An unmet requirement refuses the call
         * with {@code unsupported} and marks the tool in {@code search_tools}; unknown
         * capabilities (no server info, no configured version) never block.
         */
        public Builder requiresFeatures(String... features) {
            for (String f : features) {
                requires.add(Requirement.feature(f));
            }
            return this;
        }

        /**
         * The Keycloak version the system must run at least ({@code 26.9}); same rules.
         */
        public Builder minVersion(String minimum) {
            requires.add(Requirement.minVersion(minimum));
            return this;
        }

        /**
         * The newest Keycloak version the tool works with, inclusive at the precision
         * given ({@code "26"} covers every 26.x); unbounded by default. On a newer server
         * the tool is refused with a message that says the dependency was removed,
         * instead of "enable the feature". A handler that must serve several versions
         * branches on {@link ToolCall#capabilities()} instead.
         */
        public Builder maxVersion(String maximum) {
            requires.add(Requirement.maxVersion(maximum));
            return this;
        }

        /** Additional per-call access predicate; several must all allow. */
        public Builder access(AccessCheck check) {
            accessChecks.add(check);
            return this;
        }

        /**
         * Whether the tool may run under delegated access (default
         * {@link Delegation#ALLOWED}).
         */
        public Builder delegation(Delegation delegation) {
            this.delegation = delegation;
            return this;
        }

        /** The result carries a secret; see {@link ToolSpec#sensitiveResult()}. */
        public Builder sensitiveResult() {
            this.sensitiveResult = true;
            return this;
        }

        public Builder handler(ToolHandler handler) {
            this.handler = handler;
            return this;
        }

        /**
         * @throws IllegalStateException when no level was declared: every tool says
         * {@link #read()}, {@link #write()} or {@link #destructive()}, the level drives
         * the read-only filter, the confirmation and the explicit-target rule, so it is
         * never assumed
         */
        public ToolSpec build() {
            if (level == null) {
                throw new IllegalStateException("Tool '" + name + "' declares no level: call read(), write() or"
                        + " destructive() on the builder (READ is not assumed, the level drives read-only mode,"
                        + " confirmation and the explicit-target rule)");
            }
            boolean idem = idempotent != null ? idempotent : level == ToolLevel.READ;
            return new ToolSpec(name, title, description, category, level, idem, inputSchema, synonyms, hot,
                    realmScoped, api, requiredRoles, requires, accessChecks, delegation, handler, sensitiveResult);
        }
    }
}
