package org.keycloak.mcp.tools;

import java.util.List;
import java.util.Map;

import org.keycloak.admin.client.resource.GroupsResource;
import org.keycloak.mcp.catalog.Category;
import org.keycloak.mcp.catalog.ToolCall;
import org.keycloak.mcp.catalog.ToolResult;
import org.keycloak.mcp.catalog.ToolSpec;
import org.keycloak.mcp.keycloak.KeycloakAdmin;
import org.keycloak.mcp.keycloak.Views;
import org.keycloak.mcp.spi.ToolProviderContext;
import org.keycloak.representations.idm.GroupRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;

/**
 * GROUPS: list/create/delete, membership, group role mappings.
 */
public class GroupToolProvider extends AbstractToolProvider {

    @Override
    public String id() {
        return "groups";
    }

    @Override
    public String displayName() {
        return "Groups";
    }

    @Override
    public String description() {
        return "Groups, group membership and group role mappings.";
    }

    @Override
    public int order() {
        return 20;
    }

    @Override
    public List<ToolSpec> tools(ToolProviderContext context) {
        return List.of(
                tool("keycloak_group_list")
                        .title("List groups")
                        .description("List groups (optionally filtered by name) with id and path.")
                        .category(Category.GROUPS).read()
                        .synonyms("teams", "departments", "find group", "search groups", "hierarchy")
                        .schema(schema()
                                .string("search", "Filter by (partial) group name")
                                .pagination())
                        .handler(this::list)
                        .roles("query-groups")
                        .api(get(R + "/groups").query("search", "first", "max"))
                        .build(),
                tool("keycloak_group_create")
                        .title("Create group")
                        .description("Create a top-level group, or a subgroup when parentId is given.")
                        .category(Category.GROUPS).write()
                        .synonyms("add group", "new team", "subgroup", "nested")
                        .schema(schema()
                                .string("name", "Group name").required()
                                .string("parentId", "Parent group (id, path or name) for a subgroup"))
                        .handler(this::create)
                        .roles("manage-users")
                        .api(post(R + "/groups").body("GroupRepresentation", "name"), post(R + "/groups/{group-id}/children").path("group-id", "parentId").body("GroupRepresentation", "name"))
                        .build(),
                tool("keycloak_group_delete")
                        .title("Delete group")
                        .description("Delete a group and its subgroups; members are kept as users.")
                        .category(Category.GROUPS).destructive()
                        .synonyms("remove group", "purge team")
                        .schema(schema().string("id", GROUP_ID).required())
                        .handler(this::delete)
                        .roles("manage-users")
                        .api(delete(R + "/groups/{group-id}").path("group-id", "id"))
                        .build(),
                tool("keycloak_group_members_list")
                        .title("List group members")
                        .description("Users that are direct members of a group.")
                        .category(Category.GROUPS).read()
                        .synonyms("who is in", "membership", "users in group", "members")
                        .schema(schema().string("groupId", GROUP_ID).required().pagination())
                        .handler(this::members)
                        .roles("view-users")
                        .api(get(R + "/groups/{group-id}/members").path("group-id", "groupId").query("first", "max"))
                        .build(),
                tool("keycloak_group_member_add")
                        .title("Add group member")
                        .description("Add a user to a group.")
                        .category(Category.GROUPS).write().idempotent(true)
                        .synonyms("join", "assign to group", "put user in", "membership")
                        .schema(schema()
                                .string("groupId", GROUP_ID).required()
                                .string("userId", USER_ID).required())
                        .handler(this::memberAdd)
                        .roles("manage-users")
                        .api(put(R + "/users/{user-id}/groups/{groupId}").path("user-id", "userId").path("groupId", "groupId"))
                        .build(),
                tool("keycloak_group_member_remove")
                        .title("Remove group member")
                        .description("Remove a user from a group.")
                        .category(Category.GROUPS).destructive()
                        .synonyms("leave", "kick from group", "unassign group", "membership")
                        .schema(schema()
                                .string("groupId", GROUP_ID).required()
                                .string("userId", USER_ID).required())
                        .handler(this::memberRemove)
                        .roles("manage-users")
                        .api(delete(R + "/users/{user-id}/groups/{groupId}").path("user-id", "userId").path("groupId", "groupId"))
                        .build(),
                tool("keycloak_user_groups_list")
                        .title("List a user's groups")
                        .description("Groups a user belongs to.")
                        .category(Category.GROUPS).read()
                        .synonyms("membership", "member of", "which groups", "teams of user")
                        .schema(schema().string("userId", USER_ID).required())
                        .handler(this::userGroups)
                        .roles("view-users")
                        .api(get(R + "/users/{user-id}/groups").path("user-id", "userId"))
                        .build(),
                tool("keycloak_group_role_assign")
                        .title("Assign realm role to group")
                        .description("Grant a realm role to every member of a group.")
                        .category(Category.GROUPS).write().idempotent(true)
                        .synonyms("permission", "grant", "group role", "role mapping")
                        .schema(schema()
                                .string("groupId", GROUP_ID).required()
                                .string("role", "Realm role name, e.g. admin").required())
                        .handler(this::roleAssign)
                        .roles("manage-users")
                        .api(post(R + "/groups/{group-id}/role-mappings/realm").path("group-id", "groupId"))
                        .build());
    }

    ToolResult list(ToolCall call) {
        GroupsResource groups = call.kc().realm(call.realm()).groups();
        List<GroupRepresentation> found = groups.groups(call.str("search"), call.first(), call.max(), true);
        return ToolResult.ok(Views.page(Views.list(found, Views::group), call.max()));
    }

    ToolResult create(ToolCall call) {
        GroupRepresentation g = new GroupRepresentation();
        g.setName(call.str("name"));
        String id;
        if (call.has("parentId")) {
            id = KeycloakAdmin.created(call.kc().group(call.realm(), call.str("parentId")).subGroup(g));
        } else {
            id = KeycloakAdmin.created(call.kc().realm(call.realm()).groups().add(g));
        }
        GroupRepresentation created = call.kc().realm(call.realm()).groups().group(id).toRepresentation();
        return ToolResult.done("Group created", "id", id, "name", created.getName(), "path", created.getPath());
    }

    ToolResult delete(ToolCall call) {
        GroupRepresentation g = call.kc().findGroup(call.realm(), call.str("id"));
        call.kc().realm(call.realm()).groups().group(g.getId()).remove();
        return ToolResult.done("Group deleted", "id", g.getId(), "path", g.getPath());
    }

    ToolResult members(ToolCall call) {
        GroupRepresentation g = call.kc().findGroup(call.realm(), call.str("groupId"));
        List<UserRepresentation> members = call.kc().realm(call.realm()).groups().group(g.getId())
                .members(call.first(), call.max(), true);
        Map<String, Object> page = Views.page(Views.list(members, Views::user), call.max());
        page.put("group", g.getPath());
        return ToolResult.ok(page);
    }

    ToolResult memberAdd(ToolCall call) {
        GroupRepresentation g = call.kc().findGroup(call.realm(), call.str("groupId"));
        UserRepresentation u = call.kc().findUser(call.realm(), call.str("userId"));
        call.kc().realm(call.realm()).users().get(u.getId()).joinGroup(g.getId());
        return ToolResult.done("User added to group", "username", u.getUsername(), "group", g.getPath());
    }

    ToolResult memberRemove(ToolCall call) {
        GroupRepresentation g = call.kc().findGroup(call.realm(), call.str("groupId"));
        UserRepresentation u = call.kc().findUser(call.realm(), call.str("userId"));
        call.kc().realm(call.realm()).users().get(u.getId()).leaveGroup(g.getId());
        return ToolResult.done("User removed from group", "username", u.getUsername(), "group", g.getPath());
    }

    ToolResult userGroups(ToolCall call) {
        UserRepresentation u = call.kc().findUser(call.realm(), call.str("userId"));
        List<GroupRepresentation> groups = call.kc().realm(call.realm()).users().get(u.getId()).groups(0, call.maxItems(), true);
        Map<String, Object> page = Views.page(Views.list(groups, Views::group), call.maxItems());
        page.put("username", u.getUsername());
        return ToolResult.ok(page);
    }

    ToolResult roleAssign(ToolCall call) {
        GroupRepresentation g = call.kc().findGroup(call.realm(), call.str("groupId"));
        RoleRepresentation role = RoleToolProvider.realmRole(call.kc(), call.realm(), call.str("role"));
        call.kc().realm(call.realm()).groups().group(g.getId()).roles().realmLevel().add(List.of(role));
        return ToolResult.done("Role assigned to group", "group", g.getPath(), "role", role.getName());
    }
}
