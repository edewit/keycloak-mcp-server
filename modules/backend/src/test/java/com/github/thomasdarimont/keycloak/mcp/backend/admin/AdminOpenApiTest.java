package com.github.thomasdarimont.keycloak.mcp.backend.admin;

import java.lang.reflect.Method;
import java.util.Locale;
import java.util.Map;
import java.util.TreeSet;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;

import org.junit.jupiter.api.Test;

import io.quarkus.test.junit.QuarkusTest;
import io.vertx.core.json.JsonObject;

import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The hand-written {@code META-INF/openapi.yaml} describes exactly the operations
 * {@link AdminResource} has: every JAX-RS method is in the document and the document
 * names no operation the resource lacks. Served whether the admin API is on or not.
 */
@QuarkusTest
class AdminOpenApiTest {

    @Test
    void theDocumentDescribesExactlyTheResourcesOperations() {
        String body = given().accept("application/json")
            .get("/q/openapi?format=json")
            .then()
            .statusCode(200)
            .extract()
            .asString();
        JsonObject doc = new JsonObject(body);
        assertEquals("keycloak-mcp-server admin API", doc.getJsonObject("info").getString("title"));
        // the admin API is off in this profile: nothing to authorize with, and the
        // document says so
        assertFalse(doc.getJsonObject("components").containsKey("securitySchemes"));
        assertFalse(doc.containsKey("security"));
        assertTrue(doc.getJsonObject("info").getString("description").startsWith("**The admin API is off"));
        given().get("/q/swagger-ui/").then().statusCode(200);

        TreeSet<String> documented = new TreeSet<>();
        JsonObject paths = doc.getJsonObject("paths");
        for (String path : paths.fieldNames()) {
            for (String method : paths.getJsonObject(path).fieldNames()) {
                if (!method.equals("parameters")) {
                    documented.add(method.toUpperCase(Locale.ROOT) + " " + path);
                }
            }
        }
        assertEquals(resourceOperations(), documented);
    }

    @Test
    void everyErrorAnswerIsTheErrorShape() {
        JsonObject doc = new JsonObject(given().get("/q/openapi?format=json").asString());
        JsonObject paths = doc.getJsonObject("paths");
        for (String path : paths.fieldNames()) {
            JsonObject item = paths.getJsonObject(path);
            for (String method : item.fieldNames()) {
                if (method.equals("parameters")) {
                    continue;
                }
                JsonObject responses = item.getJsonObject(method).getJsonObject("responses");
                for (String status : responses.fieldNames()) {
                    if (status.charAt(0) == '4' || status.charAt(0) == '5') {
                        JsonObject r = resolve(doc, responses.getJsonObject(status));
                        String schema = r.getJsonObject("content")
                            .getJsonObject("application/json")
                            .getJsonObject("schema")
                            .getString("$ref");
                        assertEquals("#/components/schemas/Error", schema, method + " " + path + " " + status);
                    }
                }
            }
        }
    }

    private static JsonObject resolve(JsonObject doc, JsonObject node) {
        String ref = node.getString("$ref");
        if (ref == null) {
            return node;
        }
        JsonObject at = doc;
        for (String segment : ref.substring("#/".length()).split("/")) {
            at = at.getJsonObject(segment);
        }
        return at;
    }

    /**
     * {@code METHOD /admin/path} for every JAX-RS method, regexes stripped from the
     * templates.
     */
    static TreeSet<String> resourceOperations() {
        TreeSet<String> out = new TreeSet<>();
        Map<Class<?>, String> verbs = Map.of(GET.class, "GET", PUT.class, "PUT", POST.class, "POST", DELETE.class,
                "DELETE");
        for (Method m : AdminResource.class.getDeclaredMethods()) {
            Path sub = m.getAnnotation(Path.class);
            if (sub == null) {
                continue;
            }
            for (var verb : verbs.entrySet()) {
                if (m.isAnnotationPresent(verb.getKey().asSubclass(java.lang.annotation.Annotation.class))) {
                    String template = sub.value().replaceAll("\\{(\\w+):[^}]*}", "{$1}");
                    out.add(verb.getValue() + " " + AdminResource.PATH + "/" + template);
                }
            }
        }
        return out;
    }
}
