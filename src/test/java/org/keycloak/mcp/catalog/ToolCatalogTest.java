package org.keycloak.mcp.catalog;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.keycloak.mcp.Fixtures;

import io.vertx.core.json.JsonObject;

class ToolCatalogTest {

    @Test
    void realmIsFirstAndRequiredWithoutDefault() {
        ToolCatalog catalog = Fixtures.catalog(null);
        ToolSpec spec = catalog.get("keycloak_user_search").orElseThrow();
        assertEquals(List.of("realm", "search", "username", "first", "max"), spec.parameterNames());
        assertTrue(spec.inputSchema().getJsonArray("required").contains("realm"));
    }

    @Test
    void realmIsOptionalWithDefault() {
        ToolCatalog catalog = Fixtures.catalog("demo");
        ToolSpec spec = catalog.get("keycloak_user_search").orElseThrow();
        assertFalse(spec.inputSchema().containsKey("required"));
        assertTrue(spec.inputSchema().getJsonObject("properties").getJsonObject("realm").getString("description")
                .contains("demo"));
    }

    @Test
    void globalToolsHaveNoRealm() {
        ToolSpec spec = Fixtures.catalog(null).get("keycloak_server_info").orElseThrow();
        assertEquals(List.of(), spec.parameterNames());
    }

    @Test
    void paginationMaximumComesFromConfig() {
        ToolSpec spec = Fixtures.catalog(null).get("keycloak_user_search").orElseThrow();
        JsonObject max = spec.inputSchema().getJsonObject("properties").getJsonObject("max");
        assertEquals(50, max.getInteger("maximum"));
        assertEquals(20, max.getInteger("default"));
    }

    @Test
    void hotToolsFromConfigOverrideSpecFlag() {
        ToolCatalog catalog = new ToolCatalog(Fixtures.specs(), null, 10, List.of("keycloak_server_info"));
        assertTrue(catalog.get("keycloak_server_info").orElseThrow().hot());
        assertFalse(catalog.get("keycloak_user_search").orElseThrow().hot());
        // empty config list keeps the spec defaults
        assertTrue(Fixtures.catalog(null).get("keycloak_user_search").orElseThrow().hot());
    }

    @Test
    void resolveIsForgiving() {
        ToolCatalog catalog = Fixtures.catalog(null);
        for (String n : List.of("keycloak_user_search", "user_search", "User-Search", "KEYCLOAK_USER_SEARCH",
                "kc_user_search", " keycloak_user_search ")) {
            assertEquals("keycloak_user_search", catalog.resolve(n).orElseThrow().name(), n);
        }
        assertTrue(catalog.resolve("keycloak_user_serach").isEmpty());
        assertTrue(catalog.resolve(null).isEmpty());
    }

    @Test
    void rejectsDuplicateNames() {
        List<ToolSpec> specs = new ArrayList<>(Fixtures.specs());
        specs.add(Fixtures.specs().get(0));
        assertThrows(IllegalStateException.class, () -> new ToolCatalog(specs, null, 10, List.of()));
    }

    @Test
    void systemArgumentOnlyWithSeveralSystems() {
        ToolCatalog single = Fixtures.catalog(null);
        assertFalse(single.get("keycloak_user_search").orElseThrow().parameterNames().contains("system"));

        ToolCatalog multi = new ToolCatalog(Fixtures.specs(), null, 50, List.of(), "", List.of("prod", "dev"), "prod");
        ToolSpec search = multi.get("keycloak_user_search").orElseThrow();
        assertEquals(List.of("system", "realm", "search", "username", "first", "max"), search.parameterNames());
        JsonObject system = search.inputSchema().getJsonObject("properties").getJsonObject("system");
        assertEquals(List.of("prod", "dev"), system.getJsonArray("enum").getList());
        assertTrue(system.getString("description").contains("prod"));
        assertFalse(search.inputSchema().getJsonArray("required").contains("system"), "default system set");
        // global tools take the system too
        assertEquals(List.of("system"), multi.get("keycloak_server_info").orElseThrow().parameterNames());

        ToolCatalog noDefault = new ToolCatalog(Fixtures.specs(), null, 50, List.of(), "", List.of("a", "b"), null);
        assertTrue(noDefault.get("keycloak_user_search").orElseThrow().inputSchema().getJsonArray("required")
                .contains("system"));
    }

    @Test
    void toolPrefixRenamesButResolvesBothForms() {
        ToolCatalog prefixed = new ToolCatalog(Fixtures.specs(), null, 50, List.of("user_search"), "prod_", List.of(), null);
        assertTrue(prefixed.get("prod_keycloak_user_search").isPresent());
        assertTrue(prefixed.get("keycloak_user_search").isEmpty());
        assertEquals("prod_keycloak_user_search", prefixed.resolve("keycloak_user_search").orElseThrow().name());
        assertEquals("prod_keycloak_user_search", prefixed.resolve("user_search").orElseThrow().name());
        assertEquals("prod_keycloak_user_search", prefixed.resolve("prod_keycloak_user_search").orElseThrow().name());
        assertTrue(prefixed.get("prod_keycloak_user_search").orElseThrow().hot(), "hot list matches without prefix");
        assertFalse(prefixed.get("prod_keycloak_user_delete").orElseThrow().hot());
    }
}
