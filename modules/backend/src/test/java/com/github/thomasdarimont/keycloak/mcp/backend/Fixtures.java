package com.github.thomasdarimont.keycloak.mcp.backend;

import java.util.List;
import java.util.Map;

import com.github.thomasdarimont.keycloak.mcp.backend.catalog.ToolCatalog;
import com.github.thomasdarimont.keycloak.mcp.catalog.Category;
import com.github.thomasdarimont.keycloak.mcp.catalog.InputSchema;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolResult;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolSpec;

/**
 * A tiny fake catalog for unit tests: one READ, one WRITE, one DESTRUCTIVE, one global
 * tool.
 */
public final class Fixtures {

    private Fixtures() {
    }

    public static List<ToolSpec> specs() {
        return List.of(
                ToolSpec.builder("keycloak_user_search")
                    .title("Search users")
                    .description("Find users by username, email or free text.")
                    .category(Category.USERS)
                    .read()
                    .hot()
                    .synonyms("find", "lookup", "account")
                    .schema(InputSchema.builder()
                        .string("search", "Free text")
                        .string("username", "Exact username")
                        .pagination())
                    .handler(call -> ToolResult.ok(List.of(Map.of("realm", call.realm(), "max", call.max(), "search",
                            String.valueOf(call.str("search"))))))
                    .build(),
                ToolSpec.builder("keycloak_user_set_enabled")
                    .title("Enable or disable a user")
                    .description("Set the enabled flag of a user.")
                    .category(Category.USERS)
                    .write()
                    .idempotent(true)
                    .synonyms("disable", "block", "lock", "activate")
                    .schema(InputSchema.builder()
                        .string("id", "User id")
                        .required()
                        .bool("enabled", "New value")
                        .required())
                    .handler(call -> ToolResult.done("updated", "id", call.str("id"), "enabled", call.bool("enabled")))
                    .build(),
                ToolSpec.builder("keycloak_user_delete")
                    .title("Delete a user")
                    .description("Permanently delete a user.")
                    .category(Category.USERS)
                    .destructive()
                    .synonyms("remove", "purge")
                    .schema(InputSchema.builder().string("id", "User id").required())
                    .handler(call -> ToolResult.done("deleted", "id", call.str("id")))
                    .build(),
                ToolSpec.builder("keycloak_server_info")
                    .title("Server info")
                    .description("Keycloak version and enabled features.")
                    .category(Category.REALM)
                    .read()
                    .global()
                    .synonyms("version")
                    .handler(call -> ToolResult.ok(Map.of("version", "test")))
                    .build(),
                ToolSpec.builder("keycloak_federation_sync")
                    .title("Sync a user federation provider")
                    .description("Trigger a full or changed users sync of an LDAP provider.")
                    .category(Category.FEDERATION)
                    .write()
                    .synonyms("ldap", "active directory", "kerberos")
                    .schema(InputSchema.builder()
                        .string("id", "Provider id")
                        .required()
                        .enumeration("action", "Sync type", "full", "changed")
                        .def("changed"))
                    .handler(call -> ToolResult.done("synced", "action", call.str("action")))
                    .build());
    }

    public static ToolCatalog catalog(String defaultRealm) {
        return new ToolCatalog(specs(), defaultRealm, 50, List.of());
    }
}
