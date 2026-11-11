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
 * Catalog entry for one tool, made with {@link #builder(String)}; the builder's methods
 * say what each part does.
 *
 * @param name what models call it ({@link #builder(String)})
 * @param title short human readable name ({@link Builder#title})
 * @param description what the tool does, for the model ({@link Builder#description})
 * @param category the area it belongs to ({@link Builder#category})
 * @param level read, write or destructive ({@link Builder#read()})
 * @param idempotent whether a repeated call has the same effect
 * ({@link Builder#idempotent})
 * @param inputSchema flat JSON schema of the tool's own parameters; the catalog adds
 * {@code realm} for realm scoped tools and clamps pagination
 * @param synonyms extra search terms, never shown to the model
 * @param hot candidate for direct exposure in hybrid mode
 * @param realmScoped whether the tool takes a {@code realm} argument
 * @param api Admin REST operations the tool relies on (checked against the OpenAPI
 * document in tests)
 * @param requires features or versions the Keycloak system must have
 * @param requiredRoles roles the server's token needs in the target realm, all of them
 * ({@link com.github.thomasdarimont.keycloak.mcp.access.RoleRef} syntax; {@code manage-x}
 * satisfies {@code view-x}, see
 * {@link com.github.thomasdarimont.keycloak.mcp.access.GrantedRoles}); empty = no role
 * needed
 * @param accessChecks extra per-call predicates, evaluated after roles and before
 * confirmation
 * @param delegation whether the tool may run under delegated access
 * @param sensitiveResult the result carries a secret (a client secret, a generated
 * password): it still goes to the caller, who asked for it, but the audit event says so
 * and nothing the server logs itself contains it
 * @param handler what runs on a call ({@link Builder#handler})
 * @param formerNames names the tool had before ({@link Builder#formerly})
 */
public record ToolSpec(String name, String title, String description, Category category, ToolLevel level,
        boolean idempotent, JsonObject inputSchema, List<String> synonyms, boolean hot, boolean realmScoped,
        List<ApiOperation> api, Set<String> requiredRoles, List<Requirement> requires, List<AccessCheck> accessChecks,
        Delegation delegation, ToolHandler handler, boolean sensitiveResult, Set<String> formerNames) {

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
        formerNames = Set.copyOf(formerNames == null ? Set.of() : formerNames);
    }

    /** Without former names. */
    public ToolSpec(String name, String title, String description, Category category, ToolLevel level,
            boolean idempotent, JsonObject inputSchema, List<String> synonyms, boolean hot, boolean realmScoped,
            List<ApiOperation> api, Set<String> requiredRoles, List<Requirement> requires,
            List<AccessCheck> accessChecks, Delegation delegation, ToolHandler handler, boolean sensitiveResult) {
        this(name, title, description, category, level, idempotent, inputSchema, synonyms, hot, realmScoped, api,
                requiredRoles, requires, accessChecks, delegation, handler, sensitiveResult, Set.of());
    }

    public boolean isDestructive() {
        return level == ToolLevel.DESTRUCTIVE;
    }

    public boolean isReadOnly() {
        return level == ToolLevel.READ;
    }

    public ToolSpec withInputSchema(JsonObject schema) {
        return new ToolSpec(name, title, description, category, level, idempotent, schema, synonyms, hot, realmScoped,
                api, requiredRoles, requires, accessChecks, delegation, handler, sensitiveResult, formerNames);
    }

    public ToolSpec withName(String newName) {
        if (newName.equals(name)) {
            return this;
        }
        return new ToolSpec(newName, title, description, category, level, idempotent, inputSchema, synonyms, hot,
                realmScoped, api, requiredRoles, requires, accessChecks, delegation, handler, sensitiveResult,
                formerNames);
    }

    public ToolSpec withHot(boolean hotFlag) {
        return new ToolSpec(name, title, description, category, level, idempotent, inputSchema, synonyms, hotFlag,
                realmScoped, api, requiredRoles, requires, accessChecks, delegation, handler, sensitiveResult,
                formerNames);
    }

    /** Parameter names declared in the (effective) schema, in declaration order. */
    public List<String> parameterNames() {
        JsonObject props = inputSchema.getJsonObject("properties");
        return props == null ? List.of() : new ArrayList<>(props.fieldNames());
    }

    /**
     * A builder for a tool. Tool providers usually call
     * {@code AbstractToolProvider.tool(name)}, which is this.
     *
     * @param name the tool's name as models call it: snake_case, starting with
     * {@code keycloak_} like the built-in tools ({@code keycloak_acme_user_summary}),
     * unique among all tools; the server may put {@code kc-mcp.tool-prefix} before it
     */
    public static Builder builder(String name) {
        return new Builder(name);
    }

    /**
     * Declares one tool; {@link #build()} makes the {@link ToolSpec}. Required: a
     * {@link #title}, a {@link #description}, a {@link #category}, a level
     * ({@link #read()}, {@link #write()} or {@link #destructive()}) and a
     * {@link #handler}. Everything else has a default.
     * {@snippet :
     * tool("keycloak_acme_user_offboard").title("Offboard user")
     *     .description("Disables a user, ends their sessions and removes them from all groups.")
     *     .category(Category.USERS)
     *     .destructive()                     // needs confirmation, hidden in read-only mode
     *     .roles("manage-users")             // the server's token needs it in the target realm
     *     .synonyms("leaver", "deprovision") // search terms, never shown to the model
     *     .schema(schema().string("username", "Username or id").required())
     *     .handler(call -> offboard(call.kc(), call.realm(), call.str("username")))
     *     .build();
     * }
     */
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
        private final Set<String> formerNames = new LinkedHashSet<>();

        private Builder(String name) {
            this.name = name;
        }

        /**
         * Short human readable name, e.g. {@code Offboard user}: the MCP tool title,
         * shown by clients and in {@code search_tools} hits, searched, and used in the
         * confirmation prompt. Required.
         */
        public Builder title(String title) {
            this.title = title;
            return this;
        }

        /**
         * What the tool does, for the model: one or two sentences, at most 140 characters
         * (the built-in tools are held to it), the effect first ("Disables a user and
         * ends their sessions."). Searched by {@code search_tools}. Say in the parameter
         * descriptions what the arguments mean, not here. Required.
         */
        public Builder description(String description) {
            this.description = description;
            return this;
        }

        /**
         * The area the tool belongs to: groups the tools in {@code search_tools} and is
         * what {@code kc-mcp.allowed-categories} and the {@code categories} restriction
         * of systems and realms select by. Required.
         */
        public Builder category(Category category) {
            this.category = category;
            return this;
        }

        /**
         * The tool only reads. Kept in read-only mode and by {@code unlisted=read}, needs
         * no confirmation, idempotent by default. Enforced: while it runs the admin
         * client refuses every Admin API request but {@code GET}, {@code HEAD} and
         * {@code OPTIONS}, and the call fails as {@code read_only_violation}; a tool that
         * reads through a {@code POST} declares {@link #write()}. One of {@code read()},
         * {@code write()} or {@code destructive()} is required.
         */
        public Builder read() {
            this.level = ToolLevel.READ;
            return this;
        }

        /**
         * The tool changes Keycloak in a way that can be undone or repeated (create,
         * update, assign a role, disable a user). Hidden in read-only mode; needs
         * confirmation only where {@code confirm-writes} or {@code confirm} asks for it;
         * must name its target where {@code kc-mcp.explicit-target=write}.
         */
        public Builder write() {
            this.level = ToolLevel.WRITE;
            return this;
        }

        /**
         * The tool deletes or irreversibly changes something (delete a user, regenerate a
         * client secret). Hidden in read-only mode, always needs confirmation, must name
         * its target where {@code kc-mcp.explicit-target} is {@code destructive} or
         * {@code write}; announced by the MCP {@code destructiveHint}.
         */
        public Builder destructive() {
            this.level = ToolLevel.DESTRUCTIVE;
            return this;
        }

        /**
         * Whether calling the tool twice with the same arguments has the same effect as
         * once (MCP {@code idempotentHint}). Default: {@code true} for {@link #read()},
         * {@code false} otherwise; set it for writes such as "set enabled".
         */
        public Builder idempotent(boolean idempotent) {
            this.idempotent = idempotent;
            return this;
        }

        /**
         * The tool's own parameters, flat ({@link InputSchema#builder()}): strings,
         * numbers, booleans, string arrays and flat objects, no nesting and no
         * {@code oneOf}, which small models handle badly. Arguments arrive validated and
         * coerced. Do not declare {@code realm} or {@code system}: the catalog adds them
         * (see {@link #global()}), and clamps {@code max} to
         * {@code kc-mcp.result-max-items}. Without a schema the tool takes no parameters
         * of its own.
         */
        public Builder schema(InputSchema.Builder schema) {
            this.inputSchema = schema.build();
            return this;
        }

        /**
         * Further words people use for what the tool does ({@code "leaver"},
         * {@code "deprovision"} for offboarding): {@code search_tools} matches them, the
         * model never sees them. The built-in tools have some each; give the words the
         * name and the title do not contain.
         */
        public Builder synonyms(String... terms) {
            synonyms.addAll(List.of(terms));
            return this;
        }

        /**
         * Listed directly in the {@code hybrid} and {@code progressive} exposure modes,
         * next to {@code search_tools} and {@code execute_tool}, instead of being found
         * by search first. Keep it for the few tools nearly every session needs; a set
         * {@code kc-mcp.hot-tools} replaces every tool's own flag.
         */
        public Builder hot() {
            this.hot = true;
            return this;
        }

        /**
         * The tool works on the Keycloak system as a whole, not in a realm (server info,
         * the list of realms): no {@code realm} argument is added. By default a tool is
         * realm scoped: the catalog adds a {@code realm} parameter (optional with a
         * default realm), checks it against the allowed realms and hands the resolved
         * realm in {@link ToolCall#realm()}.
         */
        public Builder global() {
            this.realmScoped = false;
            return this;
        }

        /**
         * The Admin REST operations the tool calls ({@link ApiOperation}): documentation,
         * and for the built-in tools checked against Keycloak's OpenAPI document by a
         * test, so a removed endpoint shows up before a release. Optional.
         */
        public Builder api(ApiOperation... operations) {
            api.addAll(List.of(operations));
            return this;
        }

        /**
         * Roles the server's token needs in the target realm, all of them:
         * {@code view-users} (a {@code realm-management} role), {@code my-app.auditor} (a
         * client role) or {@code realm:offline_access} (a realm role); see
         * {@link com.github.thomasdarimont.keycloak.mcp.access.RoleRef}. {@code manage-x}
         * satisfies {@code view-x} and {@code realm-admin} all. Tools the token cannot
         * run are left out of listings and refused with the missing roles; with no admin
         * roles in the token nothing is filtered and Keycloak decides. A read tool should
         * not need a {@code manage-*} role, a write tool not only {@code view-*} ones.
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

        /**
         * A check of this tool's calls only, besides the global access checks: it sees
         * the caller, the target and the arguments and may allow, deny or demand
         * confirmation. Evaluated after the role check and before confirmation; with
         * several, all must allow.
         */
        public Builder access(AccessCheck check) {
            accessChecks.add(check);
            return this;
        }

        /**
         * Whether the tool may run when the server acts for the caller with a delegated
         * token ({@code kc-mcp.delegation}) instead of its own service account: default
         * {@link Delegation#ALLOWED}; {@link Delegation#FORBIDDEN} for tools that expose
         * secrets or reshape the realm, {@link Delegation#REQUIRED} for actions that must
         * always be attributable to a person.
         */
        public Builder delegation(Delegation delegation) {
            this.delegation = delegation;
            return this;
        }

        /**
         * Names the tool had before. A deny-list that names one still denies the tool, so
         * a restriction survives a rename; an allow-list does not carry over, the tool
         * has to be listed under its new name. Calling a former name answers that the
         * tool was renamed, it does not run the tool. A former name cannot be another
         * tool's name.
         */
        public Builder formerly(String... names) {
            for (String n : names) {
                if (n != null && !n.isBlank()) {
                    formerNames.add(n.trim());
                }
            }
            return this;
        }

        /**
         * The result carries a secret (a client secret, a generated password): the caller
         * gets it, having asked for it, but the audit event says so and nothing the
         * server logs contains it. Secrets among the arguments are declared in the schema
         * instead ({@code InputSchema...sensitive()}).
         */
        public Builder sensitiveResult() {
            this.sensitiveResult = true;
            return this;
        }

        /**
         * What the tool does when called: gets a {@link ToolCall} with the validated
         * arguments, the resolved realm and the admin client of the target system
         * ({@code call.kc()}), and returns a {@link ToolResult}. It runs after every
         * check and confirmation; an exception becomes an error result for the model.
         * Required.
         */
        public Builder handler(ToolHandler handler) {
            this.handler = handler;
            return this;
        }

        /**
         * The spec. {@link #idempotent} defaults by level.
         *
         * @throws NullPointerException when the title, description, category or handler
         * is missing
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
                    realmScoped, api, requiredRoles, requires, accessChecks, delegation, handler, sensitiveResult,
                    formerNames);
        }
    }
}
