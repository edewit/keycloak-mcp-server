package com.github.thomasdarimont.keycloak.mcp.backend.admin;

import java.util.Map;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.ExceptionMapper;
import jakarta.ws.rs.ext.Provider;

/**
 * {@link AdminException}s become their status with {@code {"error", "message"}}.
 */
@Provider
public class AdminExceptionMapper implements ExceptionMapper<AdminException> {
    @Override
    public Response toResponse(AdminException e) {
        return Response.status(e.status())
            .type(MediaType.APPLICATION_JSON)
            .entity(Map.of("error", e.code(), "message", e.getMessage()))
            .build();
    }
}
