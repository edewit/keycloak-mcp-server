package org.keycloak.mcp.keycloak;

import java.util.List;
import java.util.Map;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;

import org.keycloak.representations.idm.RoleRepresentation;

/**
 * The admin console's "Client scopes → Evaluate" tab: what a client's token would contain for a user and a set of
 * optional scopes. The Keycloak admin client has no binding for these endpoints, so this JAX-RS proxy is created
 * through {@code Keycloak.proxy(...)} and shares its authentication. Tokens come back as plain claim maps, exactly
 * as Keycloak renders them (unsigned examples, never valid credentials).
 */
@Path("/admin/realms/{realm}/clients/{client-uuid}/evaluate-scopes")
@Produces(MediaType.APPLICATION_JSON)
public interface ScopeEvaluation {

    @GET
    @Path("generate-example-access-token")
    Map<String, Object> accessToken(@PathParam("realm") String realm, @PathParam("client-uuid") String clientUuid,
            @QueryParam("scope") String scope, @QueryParam("userId") String userId,
            @QueryParam("audience") String audience);

    @GET
    @Path("generate-example-id-token")
    Map<String, Object> idToken(@PathParam("realm") String realm, @PathParam("client-uuid") String clientUuid,
            @QueryParam("scope") String scope, @QueryParam("userId") String userId,
            @QueryParam("audience") String audience);

    @GET
    @Path("generate-example-userinfo")
    Map<String, Object> userinfo(@PathParam("realm") String realm, @PathParam("client-uuid") String clientUuid,
            @QueryParam("scope") String scope, @QueryParam("userId") String userId);

    /** {@code {"samlResponse": "<xml>"}}. */
    @GET
    @Path("generate-example-saml-response")
    Map<String, Object> samlResponse(@PathParam("realm") String realm, @PathParam("client-uuid") String clientUuid,
            @QueryParam("scope") String scope, @QueryParam("userId") String userId,
            @QueryParam("audience") String audience);

    /** Effective protocol mappers: mapperName, protocolMapper, containerName, containerType. */
    @GET
    @Path("protocol-mappers")
    List<Map<String, Object>> protocolMappers(@PathParam("realm") String realm,
            @PathParam("client-uuid") String clientUuid, @QueryParam("scope") String scope);

    @GET
    @Path("scope-mappings/{roleContainerId}/granted")
    List<RoleRepresentation> grantedRoles(@PathParam("realm") String realm, @PathParam("client-uuid") String clientUuid,
            @PathParam("roleContainerId") String roleContainerId, @QueryParam("scope") String scope);

    @GET
    @Path("scope-mappings/{roleContainerId}/not-granted")
    List<RoleRepresentation> notGrantedRoles(@PathParam("realm") String realm,
            @PathParam("client-uuid") String clientUuid, @PathParam("roleContainerId") String roleContainerId,
            @QueryParam("scope") String scope);
}
