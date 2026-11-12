package com.github.thomasdarimont.keycloak.mcp.storage.audit;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * A filter over {@code kc_mcp_audit_event}, one page at a time, newest first unless a
 * {@link Builder#sort sort} says otherwise. Every filter is optional; set ones narrow
 * with AND. The page continues after the {@link Builder#after cursor} of the previous
 * page's last row, so a page stays stable while new rows arrive (keyset paging on the
 * sort key and {@code id} rather than an offset). Built with {@link #builder()}:
 *
 * <pre>
 * AuditQuery.builder().system("prod").outcome("error").sort(SortBy.TOOK).limit(25).build()
 * </pre>
 * <p>
 * Injection: the JPQL is put together from the constants of this class only (property
 * names, parameter names, the sort expressions of {@link SortBy}); every value a caller
 * supplies is a bind parameter.
 */
public final class AuditQuery {

    public static final int DEFAULT_LIMIT = 50;
    public static final int MAX_LIMIT = 500;

    /**
     * What a page can be ordered by. {@code WHEN} runs on the {@code occurred_at} index;
     * the others sort the rows the filter matches.
     */
    public enum SortBy {

        WHEN("occurredAt", true), TOOK("durationMs", true),
        /** By name; calls without one sort as the empty name, first when ascending. */
        CALLER("coalesce(callerName, '')", false);

        private final String expression;
        private final boolean numeric;

        SortBy(String expression, boolean numeric) {
            this.expression = expression;
            this.numeric = numeric;
        }

        Object keyOf(AuditEventEntity e) {
            return switch (this) {
                case WHEN -> e.occurredAt;
                case TOOK -> e.durationMs;
                case CALLER -> e.callerName == null ? "" : e.callerName;
            };
        }
    }

    private final String subject;
    private final String caller;
    private final Boolean anonymous;
    private final String system;
    private final String realm;
    private final String tool;
    private final String level;
    private final String outcome;
    private final String traceId;
    private final Long from;
    private final Long to;
    private final SortBy sort;
    private final boolean ascending;
    private final Cursor after;
    private final int limit;

    private AuditQuery(Builder b) {
        this.subject = b.subject;
        this.caller = b.caller;
        this.anonymous = b.anonymous;
        this.system = b.system;
        this.realm = b.realm;
        this.tool = b.tool;
        this.level = b.level;
        this.outcome = b.outcome;
        this.traceId = b.traceId;
        this.from = b.from;
        this.to = b.to;
        this.sort = b.sort == null ? SortBy.WHEN : b.sort;
        this.ascending = b.ascending;
        this.after = b.after;
        this.limit = b.limit <= 0 ? DEFAULT_LIMIT : Math.min(b.limit, MAX_LIMIT);
    }

    public static Builder builder() {
        return new Builder();
    }

    /** No filter, the newest {@link #DEFAULT_LIMIT}. */
    public static AuditQuery newest() {
        return builder().build();
    }

    /** What the events are ordered by. */
    public SortBy sort() {
        return sort;
    }

    /** The page size, between 1 and {@link #MAX_LIMIT}. */
    public int limit() {
        return limit;
    }

    /** Sets the filters, the order and the page of an {@link AuditQuery}. */
    public static final class Builder {

        private String subject;
        private String caller;
        private Boolean anonymous;
        private String system;
        private String realm;
        private String tool;
        private String level;
        private String outcome;
        private String traceId;
        private Long from;
        private Long to;
        private SortBy sort;
        private boolean ascending;
        private Cursor after;
        private int limit;

        private Builder() {
        }

        /** The caller's token {@code sub}, exactly (indexed). */
        public Builder subject(String subject) {
            this.subject = subject;
            return this;
        }

        /** The caller's name, exactly. */
        public Builder caller(String caller) {
            this.caller = caller;
            return this;
        }

        /**
         * {@code true}: only calls without a caller; {@code false}: only calls with one;
         * {@code null}: both.
         */
        public Builder anonymous(Boolean anonymous) {
            this.anonymous = anonymous;
            return this;
        }

        /** The system alias (indexed, with the realm). */
        public Builder system(String system) {
            this.system = system;
            return this;
        }

        public Builder realm(String realm) {
            this.realm = realm;
            return this;
        }

        /** The tool name. */
        public Builder tool(String tool) {
            this.tool = tool;
            return this;
        }

        /** {@code READ}, {@code WRITE} or {@code DESTRUCTIVE}. */
        public Builder level(String level) {
            this.level = level;
            return this;
        }

        /**
         * {@code ok}, {@code error} for every outcome but {@code ok}, or one error code.
         */
        public Builder outcome(String outcome) {
            this.outcome = outcome;
            return this;
        }

        /** The OpenTelemetry trace id, exactly (indexed). */
        public Builder traceId(String traceId) {
            this.traceId = traceId;
            return this;
        }

        /** Earliest {@code occurred_at}, epoch milliseconds, inclusive. */
        public Builder from(Long from) {
            this.from = from;
            return this;
        }

        /** Latest {@code occurred_at}, epoch milliseconds, exclusive. */
        public Builder to(Long to) {
            this.to = to;
            return this;
        }

        /** What the events are ordered by; {@link SortBy#WHEN} unless set. */
        public Builder sort(SortBy sort) {
            this.sort = sort;
            return this;
        }

        /** Smallest first; the default is largest (newest, slowest) first. */
        public Builder ascending(boolean ascending) {
            this.ascending = ascending;
            return this;
        }

        /** The cursor to continue after; it belongs to the sort it was made with. */
        public Builder after(Cursor after) {
            this.after = after;
            return this;
        }

        /**
         * The page size; {@link #DEFAULT_LIMIT} unless positive, at most
         * {@link #MAX_LIMIT}.
         */
        public Builder limit(int limit) {
            this.limit = limit;
            return this;
        }

        public AuditQuery build() {
            return new AuditQuery(this);
        }
    }

    /**
     * Where a page ended: the last row's {@code id} and its sort key, written as
     * {@code <id>.<key>} (the key is everything after the first dot).
     */
    public record Cursor(long id, String key) {

        public static Optional<Cursor> parse(String value) {
            if (value == null || value.isBlank()) {
                return Optional.empty();
            }
            int dot = value.indexOf('.');
            if (dot <= 0) {
                throw new IllegalArgumentException("cursor: <id>.<key> expected");
            }
            try {
                return Optional.of(new Cursor(Long.parseLong(value.substring(0, dot)), value.substring(dot + 1)));
            }
            catch (NumberFormatException e) {
                throw new IllegalArgumentException("cursor: <id>.<key> expected");
            }
        }

        static Cursor of(AuditEventEntity e, SortBy sort) {
            return new Cursor(e.id, String.valueOf(sort.keyOf(e)));
        }

        /**
         * The key as the type the sort compares: a number for {@code WHEN} and
         * {@code TOOK}.
         * @throws IllegalArgumentException a cursor made with another sort
         */
        public Object keyFor(SortBy sort) {
            if (!sort.numeric) {
                return key;
            }
            try {
                return Long.parseLong(key);
            }
            catch (NumberFormatException e) {
                throw new IllegalArgumentException("cursor: made with another sort");
            }
        }

        @Override
        public String toString() {
            return id + "." + key;
        }
    }

    /**
     * One page, the cursor of the next one when there is more, and how many events the
     * filter matches on all pages together.
     */
    public record Page(List<AuditEventEntity> events, Optional<Cursor> next, long total) {
    }

    /** The JPQL condition and its named parameters; {@code 1 = 1} without a filter. */
    record Where(String jpql, Map<String, Object> params) {
    }

    /**
     * The {@code order by} of the sort, {@code id} breaking ties in the same direction.
     */
    String orderBy() {
        String direction = ascending ? " asc" : " desc";
        return " order by " + sort.expression + direction + ", id" + direction;
    }

    /** The condition of one page: the filters, and what lies beyond the cursor. */
    Where where() {
        return where(true);
    }

    /** The condition of all pages together, for counting. */
    Where whereOfAllPages() {
        return where(false);
    }

    private Where where(boolean page) {
        List<String> and = new ArrayList<>();
        Map<String, Object> params = new LinkedHashMap<>();
        eq(and, params, "callerSubject", "subject", subject);
        eq(and, params, "callerName", "caller", caller);
        if (anonymous != null) {
            and.add(anonymous ? "(callerSubject is null and callerName is null)"
                    : "(callerSubject is not null or callerName is not null)");
        }
        eq(and, params, "system", "system", system);
        eq(and, params, "realm", "realm", realm);
        eq(and, params, "tool", "tool", tool);
        eq(and, params, "level", "level", level);
        if (present(outcome)) {
            if ("error".equals(outcome)) {
                and.add("outcome <> 'ok'");
            }
            else {
                eq(and, params, "outcome", "outcome", outcome);
            }
        }
        eq(and, params, "traceId", "traceId", traceId);
        if (from != null) {
            and.add("occurredAt >= :from");
            params.put("from", from);
        }
        if (to != null) {
            and.add("occurredAt < :to");
            params.put("to", to);
        }
        if (page && after != null) {
            String beyond = ascending ? " > " : " < ";
            and.add("(" + sort.expression + beyond + ":afterKey or (" + sort.expression + " = :afterKey and id" + beyond
                    + ":afterId))");
            params.put("afterKey", after.keyFor(sort));
            params.put("afterId", after.id());
        }
        return new Where(and.isEmpty() ? "1 = 1" : String.join(" and ", and), params);
    }

    private static void eq(List<String> and, Map<String, Object> params, String field, String param, String value) {
        if (present(value)) {
            and.add(field + " = :" + param);
            params.put(param, value);
        }
    }

    private static boolean present(String value) {
        return value != null && !value.isBlank();
    }
}
