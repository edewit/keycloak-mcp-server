package com.github.thomasdarimont.keycloak.mcp.audit;

import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.function.Predicate;
import java.util.function.UnaryOperator;

import com.github.thomasdarimont.keycloak.mcp.access.Caller;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolLevel;

/**
 * One finished tool call as the {@link AuditListener}s see it. Immutable; built with
 * {@link #builder()}, and changed into another event with {@link #toBuilder()} or the
 * {@code with...} methods:
 *
 * <pre>
 * AuditEvent.builder().at(Instant.now()).tool("keycloak_user_delete").level(ToolLevel.DESTRUCTIVE).outcome("ok").build()
 * </pre>
 */
public final class AuditEvent {

    private final Instant at;
    private final String tool;
    private final ToolLevel level;
    private final String system;
    private final String realm;
    private final Map<String, Object> args;
    private final String outcome;
    private final String message;
    private final String via;
    private final Caller caller;
    private final String clientName;
    private final String connectionId;
    private final Duration duration;
    private final boolean sensitiveResult;
    private final String traceId;
    private final String spanId;

    private AuditEvent(Builder b) {
        this.at = b.at;
        this.tool = b.tool;
        this.level = b.level;
        this.system = b.system;
        this.realm = b.realm;
        this.args = Map.copyOf(b.args == null ? Map.of() : b.args);
        this.outcome = b.outcome;
        this.message = b.message;
        this.via = b.via;
        this.caller = b.caller == null ? Caller.NONE : b.caller;
        this.clientName = b.clientName;
        this.connectionId = b.connectionId;
        this.duration = b.duration;
        this.sensitiveResult = b.sensitiveResult;
        this.traceId = b.traceId;
        this.spanId = b.spanId;
    }

    public static Builder builder() {
        return new Builder();
    }

    /** A builder that starts from this event. */
    public Builder toBuilder() {
        Builder b = new Builder();
        b.at = at;
        b.tool = tool;
        b.level = level;
        b.system = system;
        b.realm = realm;
        b.args = args;
        b.outcome = outcome;
        b.message = message;
        b.via = via;
        b.caller = caller;
        b.clientName = clientName;
        b.connectionId = connectionId;
        b.duration = duration;
        b.sensitiveResult = sensitiveResult;
        b.traceId = traceId;
        b.spanId = spanId;
        return b;
    }

    /** When the call finished. */
    public Instant at() {
        return at;
    }

    /** Tool name, e.g. {@code keycloak_user_delete}. */
    public String tool() {
        return tool;
    }

    /** Read, write or destructive. */
    public ToolLevel level() {
        return level;
    }

    /** Keycloak system the call targeted, or {@code null} before it was resolved. */
    public String system() {
        return system;
    }

    /** Target realm, or {@code null} for global tools and early failures. */
    public String realm() {
        return realm;
    }

    /**
     * The arguments as received, with password / secret values replaced by {@code
     * ***}; never {@code null}.
     */
    public Map<String, Object> args() {
        return args;
    }

    /**
     * {@code ok} or the error code ({@code forbidden}, {@code not_found}, {@code
     * invalid_arguments}, ...).
     */
    public String outcome() {
        return outcome;
    }

    /** Error message, or {@code null} on success. */
    public String message() {
        return message;
    }

    /** {@code direct} or {@code execute_tool}. */
    public String via() {
        return via;
    }

    /**
     * Who acted, with claims but without the raw token; {@link Caller#NONE} on anonymous
     * connections.
     */
    public Caller caller() {
        return caller;
    }

    /** The MCP client's name from {@code initialize}, or {@code -}. */
    public String clientName() {
        return clientName;
    }

    /** The MCP connection id, or {@code -}. */
    public String connectionId() {
        return connectionId;
    }

    /** Wall time of the call. */
    public Duration duration() {
        return duration;
    }

    /**
     * Whether the tool's result carried a secret the caller asked for (a client secret, a
     * generated password); the event never contains it.
     */
    public boolean sensitiveResult() {
        return sensitiveResult;
    }

    /**
     * The OpenTelemetry trace the call ran in (32 hex digits), or {@code null} when
     * tracing is off; with it the call is found in a tracing or logging system.
     */
    public String traceId() {
        return traceId;
    }

    /** The span of that trace (16 hex digits), or {@code null}. */
    public String spanId() {
        return spanId;
    }

    public boolean succeeded() {
        return "ok".equals(outcome);
    }

    /** The same event with other arguments. */
    public AuditEvent withArgs(Map<String, Object> newArgs) {
        return toBuilder().args(newArgs).build();
    }

    /**
     * The same event with the values of the matching argument names replaced by what the
     * function returns for them ({@code mapArgs(k -> k.equals("email"), v -> "***")}); a
     * {@code null} result removes the argument.
     */
    public AuditEvent mapArgs(Predicate<String> argName, UnaryOperator<Object> value) {
        Map<String, Object> out = new LinkedHashMap<>();
        args.forEach((k, v) -> {
            Object mapped = argName.test(k) ? value.apply(v) : v;
            if (mapped != null) {
                out.put(k, mapped);
            }
        });
        return withArgs(out);
    }

    /** The same event with another message ({@code null} for none). */
    public AuditEvent withMessage(String newMessage) {
        return toBuilder().message(newMessage).build();
    }

    /** The same event with another caller ({@code null} for {@link Caller#NONE}). */
    public AuditEvent withCaller(Caller newCaller) {
        return toBuilder().caller(newCaller).build();
    }

    /**
     * The same event with the ids of the trace and span the call ran in ({@code null} for
     * none).
     */
    public AuditEvent withTrace(String newTraceId, String newSpanId) {
        return toBuilder().traceId(newTraceId).spanId(newSpanId).build();
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof AuditEvent e && Objects.equals(at, e.at) && Objects.equals(tool, e.tool)
                && Objects.equals(level, e.level) && Objects.equals(system, e.system) && Objects.equals(realm, e.realm)
                && Objects.equals(args, e.args) && Objects.equals(outcome, e.outcome)
                && Objects.equals(message, e.message) && Objects.equals(via, e.via) && Objects.equals(caller, e.caller)
                && Objects.equals(clientName, e.clientName) && Objects.equals(connectionId, e.connectionId)
                && Objects.equals(duration, e.duration) && sensitiveResult == e.sensitiveResult
                && Objects.equals(traceId, e.traceId) && Objects.equals(spanId, e.spanId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(at, tool, level, system, realm, args, outcome, message, via, caller, clientName,
                connectionId, duration, sensitiveResult, traceId, spanId);
    }

    @Override
    public String toString() {
        return "AuditEvent[at=" + at + ", tool=" + tool + ", level=" + level + ", system=" + system + ", realm=" + realm
                + ", args=" + args + ", outcome=" + outcome + ", message=" + message + ", via=" + via + ", caller="
                + caller + ", clientName=" + clientName + ", connectionId=" + connectionId + ", duration=" + duration
                + ", sensitiveResult=" + sensitiveResult + ", traceId=" + traceId + ", spanId=" + spanId + "]";
    }

    /** Sets the fields of an {@link AuditEvent}; what is left out is {@code null}. */
    public static final class Builder {

        private Instant at;
        private String tool;
        private ToolLevel level;
        private String system;
        private String realm;
        private Map<String, Object> args;
        private String outcome;
        private String message;
        private String via;
        private Caller caller;
        private String clientName;
        private String connectionId;
        private Duration duration;
        private boolean sensitiveResult;
        private String traceId;
        private String spanId;

        private Builder() {
        }

        public Builder at(Instant at) {
            this.at = at;
            return this;
        }

        public Builder tool(String tool) {
            this.tool = tool;
            return this;
        }

        public Builder level(ToolLevel level) {
            this.level = level;
            return this;
        }

        public Builder system(String system) {
            this.system = system;
            return this;
        }

        public Builder realm(String realm) {
            this.realm = realm;
            return this;
        }

        public Builder args(Map<String, Object> args) {
            this.args = args;
            return this;
        }

        public Builder outcome(String outcome) {
            this.outcome = outcome;
            return this;
        }

        public Builder message(String message) {
            this.message = message;
            return this;
        }

        public Builder via(String via) {
            this.via = via;
            return this;
        }

        public Builder caller(Caller caller) {
            this.caller = caller;
            return this;
        }

        public Builder clientName(String clientName) {
            this.clientName = clientName;
            return this;
        }

        public Builder connectionId(String connectionId) {
            this.connectionId = connectionId;
            return this;
        }

        public Builder duration(Duration duration) {
            this.duration = duration;
            return this;
        }

        public Builder sensitiveResult(boolean sensitiveResult) {
            this.sensitiveResult = sensitiveResult;
            return this;
        }

        public Builder traceId(String traceId) {
            this.traceId = traceId;
            return this;
        }

        public Builder spanId(String spanId) {
            this.spanId = spanId;
            return this;
        }

        public AuditEvent build() {
            return new AuditEvent(this);
        }
    }
}
