package com.github.thomasdarimont.keycloak.mcp.backend.admin;

import java.util.Map;
import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;
import jakarta.ws.rs.ext.ExceptionMapper;
import jakarta.ws.rs.ext.Provider;

/**
 * The admin API over HTTP; {@link AdminAccessFilter} lets requests through,
 * {@link AdminSystems} does the work. Bodies and representations are plain maps, Jackson
 * turns them into JSON.
 *
 * <pre>
 * PUT    /admin/systems/{alias}              register or replace (body: the systems file fields, signingKey)
 * POST   /admin/systems                      same, alias in the body
 * GET    /admin/systems                      every known system with its source repository
 * GET    /admin/systems/{alias}
 * DELETE /admin/systems/{alias}              remove from the mutable repository (keys stay in the vault)
 * POST   /admin/systems/{alias}/signing-key  rotate the key
 * </pre>
 */
@Path(AdminResource.PATH)
@Produces(MediaType.APPLICATION_JSON)
public class AdminResource {

    public static final String PATH = "/admin";

    @Inject
    AdminSystems admin;

    @GET
    @Path("systems")
    public Map<String, Object> list(@Context UriInfo uri, @Context HttpHeaders headers) {
        return admin.list(publicBase(uri, headers));
    }

    @GET
    @Path("systems/{alias}")
    public Map<String, Object> get(@PathParam("alias") String alias, @Context UriInfo uri,
            @Context HttpHeaders headers) {
        return admin.get(alias, publicBase(uri, headers));
    }

    @PUT
    @Path("systems/{alias}")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response put(@PathParam("alias") String alias, Map<String, Object> body, @Context UriInfo uri,
            @Context HttpHeaders headers) {
        return saved(admin.save(body, alias, publicBase(uri, headers)));
    }

    @POST
    @Path("systems")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response post(Map<String, Object> body, @Context UriInfo uri, @Context HttpHeaders headers) {
        return saved(admin.save(body, null, publicBase(uri, headers)));
    }

    @DELETE
    @Path("systems/{alias}")
    public Response delete(@PathParam("alias") String alias) {
        admin.delete(alias);
        return Response.noContent().build();
    }

    @POST
    @Path("systems/{alias}/signing-key")
    public Map<String, Object> rotate(@PathParam("alias") String alias, @Context UriInfo uri,
            @Context HttpHeaders headers) {
        return admin.rotate(alias, publicBase(uri, headers));
    }

    private static Response saved(AdminSystems.Saved saved) {
        return Response.status(saved.replaced() ? 200 : 201).entity(saved.representation()).build();
    }

    /**
     * Scheme and host the caller used, the base of the JWKS URL: {@code X-Forwarded-*}
     * first (or let {@code quarkus.http.proxy.proxy-address-forwarding} fold them into
     * the request), else the request's own.
     */
    static String publicBase(UriInfo uri, HttpHeaders headers) {
        String proto = headers.getHeaderString("X-Forwarded-Proto");
        String host = headers.getHeaderString("X-Forwarded-Host");
        if (proto == null || proto.isBlank()) {
            proto = uri.getBaseUri().getScheme();
        }
        if (host == null || host.isBlank()) {
            host = uri.getBaseUri().getAuthority();
        }
        return proto + "://" + host;
    }

    /** {@link AdminException}s become their status with {@code {"error", "message"}}. */
    @Provider
    public static class AdminExceptionMapper implements ExceptionMapper<AdminException> {
        @Override
        public Response toResponse(AdminException e) {
            return Response.status(e.status())
                .type(MediaType.APPLICATION_JSON)
                .entity(Map.of("error", e.code(), "message", e.getMessage()))
                .build();
        }
    }
}
