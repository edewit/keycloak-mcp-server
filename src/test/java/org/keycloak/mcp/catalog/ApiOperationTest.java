package org.keycloak.mcp.catalog;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

class ApiOperationTest {

    @Test
    void factoriesCoverAllMethods() {
        assertEquals("get", ApiOperation.get("/x").method());
        assertEquals("post", ApiOperation.post("/x").method());
        assertEquals("put", ApiOperation.put("/x").method());
        assertEquals("delete", ApiOperation.delete("/x").method());
        assertEquals("patch", ApiOperation.patch("/x").method());
        assertEquals("head", ApiOperation.head("/x").method());
        assertEquals("options", ApiOperation.of("OPTIONS", "/x").method());
        assertThrows(IllegalArgumentException.class, () -> ApiOperation.of("fetch", "/x"));
    }

    @Test
    void buildersAreImmutableAndAccumulate() {
        ApiOperation base = ApiOperation.put("/admin/realms/{realm}/users/{user-id}");
        ApiOperation bound = base.path("user-id", "id").query("first", "max").queryAs("client_id", "clientId")
                .fixedQuery("type").body("UserRepresentation", "email").body("UserRepresentation", "enabled");
        assertTrue(base.pathParams().isEmpty());
        assertEquals(Map.of("user-id", "id"), bound.pathParams());
        assertEquals(Map.of("first", "first", "max", "max", "client_id", "clientId"), bound.queryParams());
        assertEquals(List.of("type"), bound.fixedQuery());
        assertEquals(List.of("email", "enabled"), bound.bodyFields());
        assertEquals(List.of("realm", "user-id"), bound.templateParams());
        assertTrue(bound.isSpecified());
        assertEquals("PUT /admin/realms/{realm}/users/{user-id}", bound.toString());
    }

    @Test
    void unspecifiedKeepsMethodValidation() {
        ApiOperation op = ApiOperation.unspecified("POST", "/admin/realms/{realm}/user-storage/{id}/sync", "not published");
        assertFalse(op.isSpecified());
        assertEquals("post", op.method());
        assertEquals("not published", op.unspecified());
        assertThrows(IllegalArgumentException.class, () -> ApiOperation.unspecified("nope", "/x", "r"));
    }
}
