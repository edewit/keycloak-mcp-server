package org.keycloak.mcp.catalog;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

import jakarta.inject.Inject;

import org.junit.jupiter.api.Test;

import io.quarkus.test.junit.QuarkusTest;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

/**
 * Checks every tool's {@link ApiOperation} bindings against the Keycloak Admin REST OpenAPI document of a concrete
 * server version ({@code src/test/resources/openapi/keycloak-<version>.json}, pick with
 * {@code -Dkeycloak.openapi.version=...}):
 * <ul>
 * <li>operation exists and is not deprecated,</li>
 * <li>every path template parameter is bound to an existing tool argument,</li>
 * <li>every bound query parameter exists in the spec, with a compatible type and enum,</li>
 * <li>every body field exists in the referenced schema, with a compatible type when the tool has an argument of
 * the same name.</li>
 * </ul>
 * Spec query parameters the tool does not expose are reported, not failed.
 */
@QuarkusTest
class OpenApiAlignmentTest {

    static final String VERSION = System.getProperty("keycloak.openapi.version", "26.8.1");

    @Inject
    ToolCatalog catalog;

    @Test
    void toolsMatchTheOpenApiDocument() throws IOException {
        JsonObject spec = loadSpec();
        JsonObject paths = spec.getJsonObject("paths");
        JsonObject schemas = spec.getJsonObject("components").getJsonObject("schemas");
        List<String> problems = new ArrayList<>();
        Map<String, Set<String>> unexposed = new TreeMap<>();
        List<String> unspecified = new ArrayList<>();
        int operations = 0;

        for (ToolSpec tool : catalog.all()) {
            if (tool.name().startsWith("keycloak_acme_")) {
                continue;
            }
            if (tool.api().isEmpty()) {
                problems.add(tool.name() + ": no ApiOperation declared");
                continue;
            }
            JsonObject toolProps = tool.inputSchema().getJsonObject("properties");
            for (ApiOperation op : tool.api()) {
                operations++;
                String where = tool.name() + " " + op;
                if (!op.isSpecified()) {
                    unspecified.add(where + " (" + op.unspecified() + ")");
                    continue;
                }
                JsonObject pathItem = paths.getJsonObject(op.path());
                JsonObject operation = pathItem == null ? null : pathItem.getJsonObject(op.method());
                if (operation == null) {
                    problems.add(where + ": operation not in spec" + nearest(paths, op.path()));
                    continue;
                }
                if (Boolean.TRUE.equals(operation.getBoolean("deprecated"))) {
                    problems.add(where + ": operation is deprecated");
                }
                // path parameters
                for (String templateParam : op.templateParams()) {
                    if (templateParam.equals(InputSchema.REALM)) {
                        if (!tool.realmScoped()) {
                            problems.add(where + ": path has {realm} but tool is global");
                        }
                        continue;
                    }
                    String toolArg = op.pathParams().get(templateParam);
                    if (toolArg == null) {
                        problems.add(where + ": path parameter {" + templateParam + "} not bound");
                    } else if (!toolProps.containsKey(toolArg)) {
                        problems.add(where + ": path parameter {" + templateParam + "} bound to unknown tool argument '"
                                + toolArg + "'");
                    }
                }
                for (String bound : op.pathParams().keySet()) {
                    if (!op.templateParams().contains(bound)) {
                        problems.add(where + ": bound path parameter {" + bound + "} is not in the template");
                    }
                }
                // query parameters
                Map<String, JsonObject> specQuery = new TreeMap<>();
                collectParams(pathItem.getJsonArray("parameters"), specQuery);
                collectParams(operation.getJsonArray("parameters"), specQuery);
                for (Map.Entry<String, String> e : op.queryParams().entrySet()) {
                    JsonObject specParam = specQuery.get(e.getKey());
                    if (specParam == null) {
                        problems.add(where + ": query parameter '" + e.getKey() + "' not in spec; spec has "
                                + specQuery.keySet());
                        continue;
                    }
                    JsonObject toolParam = toolProps.getJsonObject(e.getValue());
                    if (toolParam == null) {
                        problems.add(where + ": query parameter '" + e.getKey() + "' bound to unknown tool argument '"
                                + e.getValue() + "'");
                        continue;
                    }
                    checkType(where + " query '" + e.getKey() + "'", toolParam, specParam.getJsonObject("schema"),
                            schemas, problems);
                }
                for (String fixed : op.fixedQuery()) {
                    if (!specQuery.containsKey(fixed)) {
                        problems.add(where + ": fixed query parameter '" + fixed + "' not in spec");
                    }
                }
                Set<String> notExposed = new TreeSet<>(specQuery.keySet());
                notExposed.removeAll(op.queryParams().keySet());
                notExposed.removeAll(op.fixedQuery());
                notExposed.remove("briefRepresentation");
                if (!notExposed.isEmpty() && "get".equals(op.method())) {
                    unexposed.computeIfAbsent(tool.name(), k -> new TreeSet<>()).addAll(notExposed);
                }
                // body
                if (op.bodySchema() != null) {
                    JsonObject schema = schemas.getJsonObject(op.bodySchema());
                    if (schema == null) {
                        problems.add(where + ": body schema '" + op.bodySchema() + "' not in spec");
                        continue;
                    }
                    String declared = requestBodySchema(operation);
                    if (declared != null && !declared.equals(op.bodySchema())) {
                        problems.add(where + ": operation body is " + declared + ", not " + op.bodySchema());
                    }
                    JsonObject props = schema.getJsonObject("properties", new JsonObject());
                    for (String field : op.bodyFields()) {
                        JsonObject specField = props.getJsonObject(field);
                        if (specField == null) {
                            problems.add(where + ": body field " + op.bodySchema() + "." + field + " not in spec");
                            continue;
                        }
                        JsonObject toolParam = toolProps.getJsonObject(field);
                        if (toolParam != null) {
                            checkType(where + " body field '" + field + "'", toolParam, specField, schemas, problems);
                        }
                    }
                }
            }
        }

        System.out.println("OpenAPI " + VERSION + ": " + operations + " operations checked across "
                + catalog.size() + " tools");
        unspecified.forEach(u -> System.out.println("  not in spec: " + u));
        unexposed.forEach((t, ps) -> System.out.println("  " + t + " does not expose " + ps));
        assertTrue(problems.isEmpty(), "OpenAPI " + VERSION + " alignment problems:\n  " + String.join("\n  ", problems));
    }

    private static void collectParams(JsonArray params, Map<String, JsonObject> out) {
        if (params == null) {
            return;
        }
        for (Object o : params) {
            JsonObject p = (JsonObject) o;
            if ("query".equals(p.getString("in"))) {
                out.put(p.getString("name"), p);
            }
        }
    }

    private static String requestBodySchema(JsonObject operation) {
        JsonObject body = operation.getJsonObject("requestBody");
        if (body == null) {
            return null;
        }
        JsonObject json = body.getJsonObject("content", new JsonObject()).getJsonObject("application/json");
        if (json == null) {
            return null;
        }
        String ref = json.getJsonObject("schema", new JsonObject()).getString("$ref");
        return ref == null ? null : ref.substring(ref.lastIndexOf('/') + 1);
    }

    /** Resolves {@code $ref} and compares the JSON types; a string tool argument may feed an array-of-strings. */
    private static void checkType(String where, JsonObject toolParam, JsonObject specSchema, JsonObject schemas,
            List<String> problems) {
        if (specSchema == null) {
            return;
        }
        String ref = specSchema.getString("$ref");
        if (ref != null) {
            specSchema = schemas.getJsonObject(ref.substring(ref.lastIndexOf('/') + 1));
            if (specSchema == null) {
                return;
            }
        }
        String specType = specSchema.getString("type", "object");
        String toolType = toolParam.getString("type");
        boolean ok = switch (toolType) {
            case "integer" -> specType.equals("integer") || specType.equals("number");
            case "number" -> specType.equals("number") || specType.equals("integer");
            case "boolean" -> specType.equals("boolean");
            case "array" -> specType.equals("array");
            case "object" -> specType.equals("object");
            default -> specType.equals("string") || specType.equals("array")
                    && "string".equals(specSchema.getJsonObject("items", new JsonObject()).getString("type"));
        };
        if (!ok) {
            problems.add(where + ": tool type " + toolType + " vs spec type " + specType);
        }
        JsonArray specEnum = specSchema.getJsonArray("enum");
        JsonArray toolEnum = toolParam.getJsonArray("enum");
        if (specEnum != null && toolEnum != null) {
            for (Object v : toolEnum) {
                if (!specEnum.contains(v)) {
                    problems.add(where + ": enum value " + v + " not in spec enum " + specEnum.encode());
                }
            }
        }
    }

    private static String nearest(JsonObject paths, String path) {
        String prefix = path.substring(0, Math.max(path.lastIndexOf('/'), 1));
        List<String> candidates = paths.fieldNames().stream().filter(p -> p.startsWith(prefix)).sorted().limit(6)
                .toList();
        return candidates.isEmpty() ? "" : "; similar: " + candidates;
    }

    static JsonObject loadSpec() throws IOException {
        String resource = "/openapi/keycloak-" + VERSION + ".json";
        try (InputStream in = OpenApiAlignmentTest.class.getResourceAsStream(resource)) {
            if (in == null) {
                throw new IOException("Missing " + resource + "; download it from https://www.keycloak.org/docs-api/"
                        + VERSION + "/rest-api/openapi.json");
            }
            return new JsonObject(Buffer.buffer(new String(in.readAllBytes(), StandardCharsets.UTF_8)));
        }
    }
}
