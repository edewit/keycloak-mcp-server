package com.github.thomasdarimont.keycloak.mcp.catalog;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * One Keycloak Admin REST operation a tool relies on, and how the tool's arguments map
 * onto it. Purely declarative: the handlers still go through the Java admin client. The
 * metadata lets a test check every tool against the published OpenAPI document of a
 * concrete Keycloak version (operation present and not deprecated, query parameters and
 * body fields exist with compatible types).
 *
 * @param pathParams spec path parameter -> tool argument ({@code realm} is bound
 * implicitly for realm scoped tools)
 * @param queryParams spec query parameter -> tool argument
 * @param fixedQuery spec query parameters the handler always sets itself (checked for
 * existence only)
 * @param bodySchema name of the request body schema in {@code components.schemas}, or
 * {@code null}
 * @param bodyFields properties of that schema the tool sets
 * @param unspecified reason why the operation is not in the OpenAPI document
 * ({@code null} when it is)
 */
public record ApiOperation(String method, String path, Map<String, String> pathParams, Map<String, String> queryParams,
        List<String> fixedQuery, String bodySchema, List<String> bodyFields, String unspecified) {

    private static final Pattern TEMPLATE_PARAM = Pattern.compile("\\{([^}]+)}");
    /** HTTP methods the OpenAPI document can describe. */
    public static final List<String> METHODS = List.of("get", "post", "put", "delete", "patch", "head", "options");

    public ApiOperation {
        method = method.toLowerCase(Locale.ROOT);
        pathParams = Map.copyOf(pathParams == null ? Map.of() : pathParams);
        queryParams = Map.copyOf(queryParams == null ? Map.of() : queryParams);
        fixedQuery = List.copyOf(fixedQuery == null ? List.of() : fixedQuery);
        bodyFields = List.copyOf(bodyFields == null ? List.of() : bodyFields);
    }

    public static ApiOperation get(String path) {
        return of("get", path);
    }

    public static ApiOperation post(String path) {
        return of("post", path);
    }

    public static ApiOperation put(String path) {
        return of("put", path);
    }

    public static ApiOperation delete(String path) {
        return of("delete", path);
    }

    public static ApiOperation patch(String path) {
        return of("patch", path);
    }

    public static ApiOperation head(String path) {
        return of("head", path);
    }

    public static ApiOperation of(String method, String path) {
        String m = method.toLowerCase(Locale.ROOT);
        if (!METHODS.contains(m)) {
            throw new IllegalArgumentException("Unsupported HTTP method '" + method + "', expected one of " + METHODS);
        }
        return new ApiOperation(method, path, Map.of(), Map.of(), List.of(), null, List.of(), null);
    }

    /** An endpoint the server has but the OpenAPI document does not list. */
    public static ApiOperation unspecified(String method, String path, String reason) {
        return of(method, path).withUnspecified(reason);
    }

    private ApiOperation withUnspecified(String reason) {
        return new ApiOperation(method, path, pathParams, queryParams, fixedQuery, bodySchema, bodyFields, reason);
    }

    public boolean isSpecified() {
        return unspecified == null;
    }

    /**
     * Marker for a path parameter the handler derives itself (e.g. the realm's internal
     * id).
     */
    public static final String DERIVED = "(derived)";

    /**
     * A path template parameter the handler fills from a lookup rather than from a tool
     * argument.
     */
    public ApiOperation derivedPath(String specParam) {
        return path(specParam, DERIVED);
    }

    /**
     * Binds a path template parameter to a tool argument, e.g.
     * {@code path("user-id", "id")}.
     */
    public ApiOperation path(String specParam, String toolArg) {
        Map<String, String> m = new LinkedHashMap<>(pathParams);
        m.put(specParam, toolArg);
        return new ApiOperation(method, path, m, queryParams, fixedQuery, bodySchema, bodyFields, unspecified);
    }

    /** Query parameters whose tool argument has the same name. */
    public ApiOperation query(String... names) {
        Map<String, String> m = new LinkedHashMap<>(queryParams);
        for (String n : names) {
            m.put(n, n);
        }
        return new ApiOperation(method, path, pathParams, m, fixedQuery, bodySchema, bodyFields, unspecified);
    }

    /**
     * A query parameter whose tool argument is named differently, e.g.
     * {@code queryAs("client_id", "clientId")}.
     */
    public ApiOperation queryAs(String specParam, String toolArg) {
        Map<String, String> m = new LinkedHashMap<>(queryParams);
        m.put(specParam, toolArg);
        return new ApiOperation(method, path, pathParams, m, fixedQuery, bodySchema, bodyFields, unspecified);
    }

    /**
     * Query parameters the handler sets to internal constants, e.g.
     * {@code fixedQuery("type")}.
     */
    public ApiOperation fixedQuery(String... names) {
        List<String> f = new ArrayList<>(fixedQuery);
        f.addAll(List.of(names));
        return new ApiOperation(method, path, pathParams, queryParams, f, bodySchema, bodyFields, unspecified);
    }

    /** Request body schema and the properties the tool writes. */
    public ApiOperation body(String schema, String... fields) {
        List<String> f = new ArrayList<>(bodyFields);
        f.addAll(List.of(fields));
        return new ApiOperation(method, path, pathParams, queryParams, fixedQuery, schema, f, unspecified);
    }

    /** Parameter names appearing in the path template, in order. */
    public List<String> templateParams() {
        List<String> out = new ArrayList<>();
        Matcher m = TEMPLATE_PARAM.matcher(path);
        while (m.find()) {
            out.add(m.group(1));
        }
        return out;
    }

    @Override
    public String toString() {
        return method.toUpperCase(Locale.ROOT) + " " + path;
    }
}
