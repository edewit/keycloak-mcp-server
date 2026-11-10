package com.github.thomasdarimont.keycloak.mcp.backend.config;

import java.util.List;

import org.junit.jupiter.api.Test;

import com.github.thomasdarimont.keycloak.mcp.config.SettingValues;

import io.vertx.core.json.JsonArray;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SettingValuesTest {

    @Test
    void booleansAndNumbersNameTheSettingWhenWrong() {
        assertTrue(SettingValues.parseBoolean(" TRUE ", "x"));
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> SettingValues.parseBoolean("yes", "kc-mcp.systems.prod.tools.read-only"));
        assertTrue(e.getMessage().startsWith("kc-mcp.systems.prod.tools.read-only must be true or false"));
        assertEquals(-5, SettingValues.parseInt(" -5", "order"));
        assertThrows(IllegalArgumentException.class, () -> SettingValues.parseInt("first", "order"));
    }

    @Test
    void listsFromConfigurationAndJson() {
        assertEquals(List.of("a", "b"), SettingValues.csv(" a, ,b,"));
        assertEquals(List.of(), SettingValues.csv(null));
        assertEquals(List.of("a", "b"), SettingValues.names("a,b", "denied"));
        assertEquals(List.of("a"), SettingValues.names(new JsonArray().add("a"), "denied"));
        assertThrows(IllegalArgumentException.class, () -> SettingValues.names(new JsonArray().add(1), "denied"));
        assertThrows(IllegalArgumentException.class, () -> SettingValues.names(true, "denied"));
    }

    @Test
    void coerceBooleanGivesBooleansBackAndLeavesTheRest() {
        assertEquals(Boolean.FALSE, SettingValues.coerceBoolean("false"));
        assertEquals("False", SettingValues.coerceBoolean("False"), "only the JSON spelling");
        assertEquals("5", SettingValues.coerceBoolean("5"));
    }
}
