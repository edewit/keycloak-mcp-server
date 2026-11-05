package com.github.thomasdarimont.keycloak.mcp.keycloak;

import jakarta.ws.rs.ProcessingException;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.Response;

import com.github.thomasdarimont.keycloak.mcp.catalog.ToolException;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolResult;

import io.vertx.core.json.JsonObject;

/**
 * Turns JAX-RS / Keycloak failures into structured tool errors.
 */
public final class KeycloakErrors {

    private KeycloakErrors() {
    }

    public static ToolResult map(Throwable t) {
        Throwable cause = t;
        for (int i = 0; i < 5 && cause != null; i++) {
            if (cause instanceof WebApplicationException wae) {
                ToolException te = fromResponse(wae.getResponse());
                return ToolResult.error(te.code(), te.getMessage(), "status", wae.getResponse().getStatus());
            }
            if (cause instanceof ProcessingException pe) {
                return ToolResult.error("keycloak_unreachable", "Cannot reach Keycloak: " + rootMessage(pe));
            }
            if (cause instanceof IllegalStateException ise && ise.getMessage() != null
                    && ise.getMessage().startsWith("Missing configuration")) {
                return ToolResult.error("server_misconfigured", ise.getMessage());
            }
            cause = cause.getCause();
        }
        return null;
    }

    public static ToolException fromResponse(Response response) {
        int status = response.getStatus();
        String detail = readMessage(response);
        String code = switch (status) {
            case 400 -> "bad_request";
            case 401 -> "unauthorized";
            case 403 -> "forbidden";
            case 404 -> "not_found";
            case 409 -> "conflict";
            default -> status >= 500 ? "keycloak_error" : "request_failed";
        };
        String message = switch (status) {
            case 401 -> "Keycloak rejected the credentials used for this call.";
            case 403 -> "The credentials used for this call lack the realm-management role for this operation.";
            case 404 -> "Not found.";
            case 409 -> "Already exists or conflicts with existing data.";
            default -> "Keycloak returned HTTP " + status + ".";
        };
        if (detail != null && !detail.isBlank()) {
            message = message + " " + detail;
        }
        return new ToolException(code, message.trim());
    }

    private static String readMessage(Response response) {
        try {
            if (!response.hasEntity()) {
                return null;
            }
            response.bufferEntity();
            String body = response.readEntity(String.class);
            if (body == null || body.isBlank()) {
                return null;
            }
            String trimmed = body.trim();
            if (trimmed.startsWith("{")) {
                JsonObject json = new JsonObject(trimmed);
                for (String key : new String[] { "errorMessage", "error_description", "message", "error" }) {
                    String v = json.getString(key, null);
                    if (v != null) {
                        return v;
                    }
                }
                return null;
            }
            return trimmed.length() > 300 ? trimmed.substring(0, 300) : trimmed;
        }
        catch (RuntimeException e) {
            return null;
        }
    }

    private static String rootMessage(Throwable t) {
        Throwable c = t;
        while (c.getCause() != null && c.getCause() != c) {
            c = c.getCause();
        }
        return c.getMessage() == null ? c.getClass().getSimpleName() : c.getMessage();
    }
}
