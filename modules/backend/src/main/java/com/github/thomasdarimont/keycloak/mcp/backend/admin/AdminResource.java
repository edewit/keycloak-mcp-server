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

/**
 * The admin API over HTTP; {@link AdminAccessFilter} lets requests through,
 * {@link AdminSystems} and {@link AdminSecrets} do the work. Bodies and representations
 * are plain maps, Jackson turns them into JSON.
 *
 * <pre>
 * PUT    /admin/systems/{alias}              register or replace (body: the systems file fields, signingKey)
 * POST   /admin/systems                      same, alias in the body
 * GET    /admin/systems                      every known system with its source repository
 * GET    /admin/systems/{alias}
 * DELETE /admin/systems/{alias}              remove from the mutable repository (keys stay in the vault)
 * POST   /admin/systems/{alias}/signing-key  rotate the key
 * GET    /admin/secrets                      the names in the vault and the systems using them, never a value
 * GET    /admin/secrets/{name}
 * PUT    /admin/secrets/{name}               store or replace (body: {"value": "..."}); referenced as vault:{name}
 * DELETE /admin/secrets/{name}               remove a secret no system refers to
 * GET    /admin/storage                      encryption state: which key ids the stored values are under
 * POST   /admin/storage/rekey                re-encrypt everything under the current kc-mcp.storage.secret-key
 * </pre>
 */
@Path(AdminResource.PATH)
@Produces(MediaType.APPLICATION_JSON)
public class AdminResource {

    public static final String PATH = "/admin";

    @Inject
    AdminSystems admin;

    @Inject
    AdminSecrets secrets;

    @Inject
    AdminStorage storage;

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

    @GET
    @Path("secrets")
    public Map<String, Object> listSecrets() {
        return secrets.list();
    }

    @GET
    @Path("secrets/{name: .+}")
    public Map<String, Object> getSecret(@PathParam("name") String name) {
        return secrets.get(name);
    }

    @PUT
    @Path("secrets/{name: .+}")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response putSecret(@PathParam("name") String name, Map<String, Object> body) {
        return saved(secrets.put(name, body));
    }

    @DELETE
    @Path("secrets/{name: .+}")
    public Response deleteSecret(@PathParam("name") String name) {
        secrets.delete(name);
        return Response.noContent().build();
    }

    @GET
    @Path("storage")
    public Map<String, Object> storage() {
        return storage.status();
    }

    @POST
    @Path("storage/rekey")
    public Map<String, Object> rekey() {
        return storage.rekey();
    }

    private static Response saved(Saved saved) {
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

}
