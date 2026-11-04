package com.github.thomasdarimont.keycloak.mcp.server.catalog;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import jakarta.inject.Inject;

import org.junit.jupiter.api.Test;

import com.github.thomasdarimont.keycloak.mcp.catalog.ToolSpec;
import com.github.thomasdarimont.keycloak.mcp.server.spi.ToolProviderRegistry;

import io.quarkus.test.junit.QuarkusTest;
import io.vertx.core.json.JsonObject;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Schema flatness, description length, naming and coverage against the reference tool
 * list.
 */
@QuarkusTest
class CatalogLintTest {

    static final Set<String> NESTED_OK = Set.of("object");

    @Inject
    ToolCatalog catalog;
    @Inject
    ToolProviderRegistry registry;

    @Test
    void schemasAreFlatAndSmallModelFriendly() {
        List<String> problems = new ArrayList<>();
        for (ToolSpec spec : catalog.all()) {
            if (!spec.name().startsWith("keycloak_")) {
                problems.add(spec.name() + ": name must start with keycloak_");
            }
            if (spec.description().length() > 140) {
                problems.add(spec.name() + ": description too long (" + spec.description().length() + ")");
            }
            if (spec.synonyms().isEmpty()) {
                problems.add(spec.name() + ": no synonyms");
            }
            if (spec.realmScoped() && spec.requiredRoles().isEmpty() && !spec.name().startsWith("keycloak_acme_")) {
                problems.add(spec.name() + ": realm scoped tool without requiredRoles");
            }
            List<com.github.thomasdarimont.keycloak.mcp.spi.RoleRef> refs = spec.requiredRoles()
                .stream()
                .map(com.github.thomasdarimont.keycloak.mcp.spi.RoleRef::parse)
                .toList();
            if (spec.isReadOnly()
                    && refs.stream().anyMatch(r -> r.isRealmManagement() && r.role().startsWith("manage-"))) {
                problems.add(spec.name() + ": READ tool requiring a manage-* role");
            }
            if (!spec.isReadOnly() && refs.stream()
                .anyMatch(r -> r.isRealmManagement()
                        && (r.role().startsWith("view-") || r.role().startsWith("query-")))) {
                problems.add(spec.name() + ": write tool requiring only a view/query role");
            }
            JsonObject schema = spec.inputSchema();
            assertEquals("object", schema.getString("type"), spec.name());
            JsonObject props = schema.getJsonObject("properties");
            for (String p : props.fieldNames()) {
                JsonObject prop = props.getJsonObject(p);
                if (prop.containsKey("oneOf") || prop.containsKey("anyOf") || prop.containsKey("allOf")) {
                    problems.add(spec.name() + "." + p + ": no oneOf/anyOf/allOf");
                }
                if ("object".equals(prop.getString("type")) && prop.containsKey("properties")) {
                    problems.add(spec.name() + "." + p + ": nested object properties");
                }
                if ("array".equals(prop.getString("type"))
                        && !"string".equals(prop.getJsonObject("items", new JsonObject()).getString("type"))) {
                    problems.add(spec.name() + "." + p + ": arrays must be arrays of strings");
                }
                if (!prop.containsKey("description")) {
                    problems.add(spec.name() + "." + p + ": missing description");
                }
            }
        }
        assertTrue(problems.isEmpty(), String.join("\n", problems));
    }

    @Test
    void builtInProvidersAreRegisteredAndDisabledOnesSkipped() {
        List<String> ids = registry.providers().stream().map(p -> p.id()).toList();
        assertTrue(ids.containsAll(List.of("users", "groups", "roles", "realm", "acme")), ids.toString());
        assertTrue(!ids.contains("disabled-demo"));
    }

    @Test
    void everyBuiltInToolIsAReferenceTool() throws IOException {
        Set<String> reference = referenceNames();
        Set<String> ours = new TreeSet<>();
        for (ToolSpec s : catalog.all()) {
            if (!s.name().startsWith("keycloak_acme_")) {
                ours.add(s.name());
            }
        }
        Set<String> extras = Set.of("keycloak_group_get", "keycloak_client_example_token",
                "keycloak_client_evaluate_scopes", "keycloak_server_features");
        Set<String> unknown = new TreeSet<>(ours);
        unknown.removeAll(reference);
        unknown.removeAll(extras);
        assertTrue(unknown.isEmpty(), "not in reference and not a declared extra: " + unknown);
        Set<String> missing = new TreeSet<>(reference);
        missing.removeAll(ours);
        System.out.println("Reference coverage: " + ours.size() + "/" + reference.size() + ", missing: " + missing);
        assertTrue(missing.isEmpty(), "reference tools not ported: " + missing);
        assertEquals(75 + extras.size(), ours.size());
    }

    static Set<String> referenceNames() throws IOException {
        Path file = Path.of("src/test/resources/reference-tool-names.txt");
        Set<String> names = new TreeSet<>();
        for (String line : Files.readAllLines(file)) {
            if (!line.isBlank() && !line.startsWith("#")) {
                names.add(line.trim());
            }
        }
        return names;
    }
}
