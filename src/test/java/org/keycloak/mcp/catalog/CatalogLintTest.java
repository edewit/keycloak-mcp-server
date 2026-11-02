package org.keycloak.mcp.catalog;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

import jakarta.inject.Inject;

import org.junit.jupiter.api.Test;
import org.keycloak.mcp.spi.ToolProviderRegistry;

import io.quarkus.test.junit.QuarkusTest;
import io.vertx.core.json.JsonObject;

/**
 * Schema flatness, description length, naming and coverage against the reference tool list.
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
        Set<String> unknown = new TreeSet<>(ours);
        unknown.removeAll(reference);
        assertTrue(unknown.isEmpty(), "not in reference: " + unknown);
        Set<String> missing = new TreeSet<>(reference);
        missing.removeAll(ours);
        System.out.println("Reference coverage: " + ours.size() + "/" + reference.size() + ", missing: " + missing);
        assertTrue(missing.isEmpty(), "reference tools not ported: " + missing);
        assertEquals(72, ours.size());
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
