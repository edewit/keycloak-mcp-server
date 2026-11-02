package org.keycloak.mcp.meta;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.keycloak.mcp.Fixtures;
import org.keycloak.mcp.catalog.ToolCatalog;
import org.keycloak.mcp.catalog.ToolResult;
import org.keycloak.mcp.exposure.ExposureMode;
import org.keycloak.mcp.exposure.ExposurePolicy;
import org.keycloak.mcp.exposure.ProgressiveState;
import org.keycloak.mcp.guard.AccessPolicy;
import org.keycloak.mcp.guard.Confirmer;
import org.keycloak.mcp.guard.InvocationContext;
import org.keycloak.mcp.guard.ToolInvoker;

import io.vertx.core.json.JsonObject;

class MetaToolsTest {

    private final ToolCatalog catalog = Fixtures.catalog(null);
    private final ProgressiveState progressive = new ProgressiveState();

    private MetaTools meta(boolean readOnly) {
        AccessPolicy policy = new AccessPolicy(readOnly, List.of());
        Confirmer confirmer = (spec, realm, args, flag, ctx) -> flag ? Confirmer.Decision.CONFIRMED
                : Confirmer.Decision.CONFIRMATION_REQUIRED;
        return new MetaTools(catalog, policy, new ToolInvoker(catalog, policy, confirmer, 50), progressive, 5);
    }

    private static Map<String, Object> payload(ToolResult r) {
        return new JsonObject(r.toJson()).getMap();
    }

    @Test
    void emptySearchListsCategories() {
        Map<String, Object> p = payload(meta(false).search(null, null, null, "c1", ExposureMode.HYBRID));
        List<?> cats = (List<?>) p.get("categories");
        assertEquals(3, cats.size());
        Map<?, ?> users = (Map<?, ?>) cats.get(0);
        assertEquals("users", users.get("category"));
        assertEquals(3, users.get("tools"));
    }

    @Test
    void searchReturnsSchemasAndHint() {
        Map<String, Object> p = payload(meta(false).search("disable user", null, 2, "c1", ExposureMode.HYBRID));
        List<?> tools = (List<?>) p.get("tools");
        assertEquals(2, tools.size());
        Map<?, ?> top = (Map<?, ?>) tools.get(0);
        assertEquals("keycloak_user_set_enabled", top.get("name"));
        assertEquals("write", top.get("level"));
        assertTrue(((Map<?, ?>) top.get("inputSchema")).containsKey("properties"));
        assertEquals(MetaTools.HINT, p.get("hint"));
    }

    @Test
    void readOnlyHidesWritesFromSearch() {
        Map<String, Object> p = payload(meta(true).search("user", null, 10, "c1", ExposureMode.HYBRID));
        List<?> tools = (List<?>) p.get("tools");
        assertEquals(List.of("keycloak_user_search"), tools.stream().map(t -> ((Map<?, ?>) t).get("name")).toList());
        Map<String, Object> cats = payload(meta(true).search("", "", null, "c1", ExposureMode.HYBRID));
        assertEquals(2, ((List<?>) cats.get("categories")).size());
    }

    @Test
    void unknownCategoryIsAnError() {
        Map<String, Object> p = payload(meta(false).search("x", "wat", null, "c1", ExposureMode.HYBRID));
        assertEquals("invalid_arguments", p.get("error"));
        assertTrue(p.containsKey("categories"));
    }

    @Test
    void progressiveModeSurfacesHits() {
        ExposurePolicy policy = new ExposurePolicy(ExposureMode.PROGRESSIVE, catalog, progressive);
        assertFalse(policy.listed("keycloak_user_delete", "c9"));
        Map<String, Object> p = payload(meta(false).search("delete user", null, 1, "c9", ExposureMode.PROGRESSIVE));
        assertEquals(true, p.get("listChanged"));
        assertTrue(policy.listed("keycloak_user_delete", "c9"));
        assertFalse(policy.listed("keycloak_user_delete", "other"));
        // second identical search changes nothing
        assertNull(payload(meta(false).search("delete user", null, 1, "c9", ExposureMode.PROGRESSIVE)).get("listChanged"));
    }

    @Test
    void exposureModes() {
        assertTrue(new ExposurePolicy(ExposureMode.DIRECT, catalog, progressive).listed("keycloak_user_delete", "c"));
        assertFalse(new ExposurePolicy(ExposureMode.DIRECT, catalog, progressive).listed(MetaTools.SEARCH_TOOLS, "c"));
        ExposurePolicy lazy = new ExposurePolicy(ExposureMode.LAZY, catalog, progressive);
        assertFalse(lazy.listed("keycloak_user_search", "c"));
        assertTrue(lazy.listed(MetaTools.EXECUTE_TOOL, "c"));
        ExposurePolicy hybrid = new ExposurePolicy(ExposureMode.HYBRID, catalog, progressive);
        assertTrue(hybrid.listed("keycloak_user_search", "c"));
        assertFalse(hybrid.listed("keycloak_user_delete", "c"));
        assertTrue(hybrid.listed("some_other_extension_tool", "c"));
    }

    @Test
    void executeHappyPath() {
        ToolResult r = meta(false).execute("user_search", Map.of("realm", "demo", "search", "bob"), null,
                InvocationContext.none());
        assertFalse(r.isError(), r.toJson());
        assertTrue(r.toJson().contains("\"search\":\"bob\""));
    }

    @Test
    void executeUnknownToolSuggests() {
        Map<String, Object> p = payload(meta(false).execute("keycloak_user_serach", Map.of(), null,
                InvocationContext.none()));
        assertEquals("unknown_tool", p.get("error"));
        List<?> dym = (List<?>) p.get("didYouMean");
        assertEquals("keycloak_user_search", ((Map<?, ?>) dym.get(0)).get("name"));
        assertTrue(((Map<?, ?>) dym.get(0)).containsKey("inputSchema"));
    }

    @Test
    void executeThreadsConfirmFlag() {
        Map<String, Object> args = Map.of("realm", "demo", "id", "1");
        assertEquals("confirmation_required",
                payload(meta(false).execute("keycloak_user_delete", args, null, InvocationContext.none())).get("error"));
        assertFalse(meta(false).execute("keycloak_user_delete", args, true, InvocationContext.none()).isError());
        // confirm inside the arguments object works too
        assertFalse(meta(false).execute("keycloak_user_delete",
                Map.of("realm", "demo", "id", "1", "confirm", true), null, InvocationContext.none()).isError());
    }

    @Test
    void executeRefusesMetaToolRecursion() {
        assertEquals("invalid_arguments",
                payload(meta(false).execute("search_tools", Map.of(), null, InvocationContext.none())).get("error"));
    }
}
