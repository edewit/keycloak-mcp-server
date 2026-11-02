package org.keycloak.mcp.tools;

import java.util.List;
import java.util.Map;

import jakarta.ws.rs.NotFoundException;

import org.keycloak.admin.client.resource.RoleMappingResource;
import org.keycloak.mcp.catalog.Category;
import org.keycloak.mcp.catalog.ToolCall;
import org.keycloak.mcp.catalog.ToolResult;
import org.keycloak.mcp.catalog.ToolSpec;
import org.keycloak.mcp.guard.ToolException;
import org.keycloak.mcp.keycloak.KeycloakAdmin;
import org.keycloak.mcp.keycloak.Views;
import org.keycloak.mcp.spi.ToolProviderContext;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;

/**
 * ROLES: realm roles, client roles and their mappings to users.
 */
public class RoleToolProvider extends AbstractToolProvider {

    @Override
    public String id() {
        return "roles";
    }

    @Override
    public String displayName() {
        return "Roles";
    }

    @Override
    public String description() {
        return "Realm roles, client roles and user role mappings.";
    }

    @Override
    public int order() {
        return 30;
    }

    @Override
    public List<ToolSpec> tools(ToolProviderContext context) {
        return List.of(
                tool("keycloak_role_list")
                        .title("List realm roles")
                        .description("Realm roles with name and description; filter by name.")
                        .category(Category.ROLES).read()
                        .synonyms("permissions", "available roles", "rbac", "authorization")
                        .schema(schema().string("search", "Filter by (partial) role name").pagination())
                        .handler(this::list)
                        .api(get(R + "/roles").query("search", "first", "max"))
                        .build(),
                tool("keycloak_client_roles_list")
                        .title("List client roles")
                        .description("Roles defined by one client, e.g. realm-management's manage-users.")
                        .category(Category.ROLES).read()
                        .synonyms("application roles", "permissions", "realm-management", "scoped roles")
                        .schema(schema().string("clientId", CLIENT_ID).required())
                        .handler(this::clientRoles)
                        .api(get(R + "/clients/{client-uuid}/roles").path("client-uuid", "clientId"))
                        .build(),
                tool("keycloak_user_roles_get")
                        .title("Get a user's realm roles")
                        .description("Realm roles mapped to a user, directly and effective (incl. groups/composites).")
                        .category(Category.ROLES).read()
                        .synonyms("permissions of user", "what can", "is admin", "role mapping", "has role")
                        .schema(schema().string("userId", USER_ID).required())
                        .handler(this::userRoles)
                        .api(get(R + "/users/{user-id}/role-mappings/realm").path("user-id", "userId"), get(R + "/users/{user-id}/role-mappings/realm/composite").path("user-id", "userId"))
                        .build(),
                tool("keycloak_user_role_assign")
                        .title("Assign realm role to user")
                        .description("Grant a realm role to a user.")
                        .category(Category.ROLES).write().idempotent(true)
                        .synonyms("grant", "make admin", "give permission", "add role", "promote")
                        .schema(schema()
                                .string("userId", USER_ID).required()
                                .string("role", "Realm role name, e.g. admin").required())
                        .handler(this::userRoleAssign)
                        .api(post(R + "/users/{user-id}/role-mappings/realm").path("user-id", "userId"))
                        .build(),
                tool("keycloak_user_role_unassign")
                        .title("Remove realm role from user")
                        .description("Revoke a realm role from a user.")
                        .category(Category.ROLES).destructive()
                        .synonyms("revoke", "take away", "remove role", "demote", "unassign")
                        .schema(schema()
                                .string("userId", USER_ID).required()
                                .string("role", "Realm role name").required())
                        .handler(this::userRoleUnassign)
                        .api(delete(R + "/users/{user-id}/role-mappings/realm").path("user-id", "userId"))
                        .build(),
                tool("keycloak_user_client_roles_get")
                        .title("Get a user's client roles")
                        .description("Client roles of one client mapped to a user.")
                        .category(Category.ROLES).read()
                        .synonyms("application permissions", "client role mapping", "realm-management roles of user")
                        .schema(schema()
                                .string("userId", USER_ID).required()
                                .string("clientId", CLIENT_ID).required())
                        .handler(this::userClientRoles)
                        .api(get(R + "/users/{user-id}/role-mappings/clients/{client-id}").path("user-id", "userId").path("client-id", "clientId"), get(R + "/users/{user-id}/role-mappings/clients/{client-id}/composite").path("user-id", "userId").path("client-id", "clientId"))
                        .build(),
                tool("keycloak_user_client_role_assign")
                        .title("Assign client role to user")
                        .description("Grant a client role (e.g. realm-management/view-users) to a user.")
                        .category(Category.ROLES).write().idempotent(true)
                        .synonyms("grant", "give permission", "add client role", "manage-users", "view-users")
                        .schema(schema()
                                .string("userId", USER_ID).required()
                                .string("clientId", CLIENT_ID).required()
                                .string("role", "Client role name").required())
                        .handler(this::userClientRoleAssign)
                        .api(post(R + "/users/{user-id}/role-mappings/clients/{client-id}").path("user-id", "userId").path("client-id", "clientId"))
                        .build(),
                tool("keycloak_user_client_role_unassign")
                        .title("Remove client role from user")
                        .description("Revoke a client role from a user.")
                        .category(Category.ROLES).destructive()
                        .synonyms("revoke", "remove client role", "unassign")
                        .schema(schema()
                                .string("userId", USER_ID).required()
                                .string("clientId", CLIENT_ID).required()
                                .string("role", "Client role name").required())
                        .handler(this::userClientRoleUnassign)
                        .api(delete(R + "/users/{user-id}/role-mappings/clients/{client-id}").path("user-id", "userId").path("client-id", "clientId"))
                        .build());
    }

    static RoleRepresentation realmRole(KeycloakAdmin kc, String realm, String name) {
        try {
            return kc.realm(realm).roles().get(name).toRepresentation();
        } catch (NotFoundException e) {
            throw ToolException.notFound("Realm role", name);
        }
    }

    static RoleRepresentation clientRole(KeycloakAdmin kc, String realm, String clientUuid, String name) {
        try {
            return kc.realm(realm).clients().get(clientUuid).roles().get(name).toRepresentation();
        } catch (NotFoundException e) {
            throw ToolException.notFound("Client role", name);
        }
    }

    ToolResult list(ToolCall call) {
        List<RoleRepresentation> roles = kc.realm(call.realm()).roles().list(call.str("search"), call.first(),
                call.max(), true);
        return ToolResult.ok(Views.page(Views.list(roles, Views::role), call.max()));
    }

    ToolResult clientRoles(ToolCall call) {
        ClientRepresentation c = kc.findClient(call.realm(), call.str("clientId"));
        List<RoleRepresentation> roles = kc.realm(call.realm()).clients().get(c.getId()).roles().list(true);
        Map<String, Object> page = Views.page(Views.list(roles, Views::role), Integer.MAX_VALUE);
        page.put("clientId", c.getClientId());
        return ToolResult.ok(page);
    }

    ToolResult userRoles(ToolCall call) {
        UserRepresentation u = kc.findUser(call.realm(), call.str("userId"));
        RoleMappingResource roles = kc.realm(call.realm()).users().get(u.getId()).roles();
        return ToolResult.ok(Map.of(
                "username", u.getUsername(),
                "realmRoles", roles.realmLevel().listAll().stream().map(RoleRepresentation::getName).sorted().toList(),
                "effectiveRealmRoles", roles.realmLevel().listEffective(true).stream().map(RoleRepresentation::getName)
                        .sorted().toList()));
    }

    ToolResult userRoleAssign(ToolCall call) {
        UserRepresentation u = kc.findUser(call.realm(), call.str("userId"));
        RoleRepresentation role = realmRole(kc, call.realm(), call.str("role"));
        kc.realm(call.realm()).users().get(u.getId()).roles().realmLevel().add(List.of(role));
        return ToolResult.done("Role assigned", "username", u.getUsername(), "role", role.getName());
    }

    ToolResult userRoleUnassign(ToolCall call) {
        UserRepresentation u = kc.findUser(call.realm(), call.str("userId"));
        RoleRepresentation role = realmRole(kc, call.realm(), call.str("role"));
        kc.realm(call.realm()).users().get(u.getId()).roles().realmLevel().remove(List.of(role));
        return ToolResult.done("Role removed", "username", u.getUsername(), "role", role.getName());
    }

    ToolResult userClientRoles(ToolCall call) {
        UserRepresentation u = kc.findUser(call.realm(), call.str("userId"));
        ClientRepresentation c = kc.findClient(call.realm(), call.str("clientId"));
        var scope = kc.realm(call.realm()).users().get(u.getId()).roles().clientLevel(c.getId());
        return ToolResult.ok(Map.of(
                "username", u.getUsername(),
                "clientId", c.getClientId(),
                "roles", scope.listAll().stream().map(RoleRepresentation::getName).sorted().toList(),
                "effectiveRoles", scope.listEffective(true).stream().map(RoleRepresentation::getName).sorted().toList()));
    }

    ToolResult userClientRoleAssign(ToolCall call) {
        UserRepresentation u = kc.findUser(call.realm(), call.str("userId"));
        ClientRepresentation c = kc.findClient(call.realm(), call.str("clientId"));
        RoleRepresentation role = clientRole(kc, call.realm(), c.getId(), call.str("role"));
        kc.realm(call.realm()).users().get(u.getId()).roles().clientLevel(c.getId()).add(List.of(role));
        return ToolResult.done("Client role assigned", "username", u.getUsername(), "clientId", c.getClientId(),
                "role", role.getName());
    }

    ToolResult userClientRoleUnassign(ToolCall call) {
        UserRepresentation u = kc.findUser(call.realm(), call.str("userId"));
        ClientRepresentation c = kc.findClient(call.realm(), call.str("clientId"));
        RoleRepresentation role = clientRole(kc, call.realm(), c.getId(), call.str("role"));
        kc.realm(call.realm()).users().get(u.getId()).roles().clientLevel(c.getId()).remove(List.of(role));
        return ToolResult.done("Client role removed", "username", u.getUsername(), "clientId", c.getClientId(),
                "role", role.getName());
    }
}
