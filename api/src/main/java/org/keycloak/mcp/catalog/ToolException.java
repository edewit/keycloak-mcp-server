package org.keycloak.mcp.catalog;

/**
 * Thrown by handlers for expected failures (not found, conflict, ...). Mapped to
 * {@code {"error": code, ...}}.
 */
public class ToolException extends RuntimeException {

    private final String code;

    public ToolException(String code, String message) {
        super(message);
        this.code = code;
    }

    public String code() {
        return code;
    }

    public static ToolException notFound(String what, String id) {
        return new ToolException("not_found", what + " '" + id + "' not found");
    }
}
