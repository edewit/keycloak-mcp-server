package com.github.thomasdarimont.keycloak.mcp.tools;

import com.github.thomasdarimont.keycloak.mcp.catalog.ApiOperation;
import com.github.thomasdarimont.keycloak.mcp.catalog.InputSchema;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolSpec;

/**
 * Base class for the built-in providers: shared schema snippets and API binding
 * shorthands. Handlers take the admin client of the call's Keycloak system from
 * {@code call.kc()}.
 */
public abstract class AbstractToolProvider implements ToolProvider {

    protected static ToolSpec.Builder tool(String name) {
        return ToolSpec.builder(name);
    }

    protected static InputSchema.Builder schema() {
        return InputSchema.builder();
    }

    protected static final String R = "/admin/realms/{realm}";

    protected static ApiOperation get(String path) {
        return ApiOperation.get(path);
    }

    protected static ApiOperation post(String path) {
        return ApiOperation.post(path);
    }

    protected static ApiOperation put(String path) {
        return ApiOperation.put(path);
    }

    protected static ApiOperation delete(String path) {
        return ApiOperation.delete(path);
    }

    protected static ApiOperation patch(String path) {
        return ApiOperation.patch(path);
    }

    protected static ApiOperation head(String path) {
        return ApiOperation.head(path);
    }

    protected static final String USER_ID = "User id (UUID) or username; pass it directly, no lookup needed";
    protected static final String GROUP_ID = "Group id (UUID), full path like /parent/child, or unique name; no lookup needed";
    protected static final String CLIENT_ID = "Client's internal id (UUID) or its clientId, e.g. my-app; no lookup needed";
}
