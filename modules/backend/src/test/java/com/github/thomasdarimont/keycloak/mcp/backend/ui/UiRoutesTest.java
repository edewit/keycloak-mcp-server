package com.github.thomasdarimont.keycloak.mcp.backend.ui;

import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class UiRoutesTest {

    @Test
    void theUrlsNameTheListeners() {
        assertEquals(List.of("http://localhost:9080/ui/"),
                UiRoutes.urls(Optional.empty(), "127.0.0.1", true, 9080, false, 8443));
        assertEquals(List.of("http://localhost:9080/ui/", "https://localhost:8443/ui/"),
                UiRoutes.urls(Optional.empty(), "0.0.0.0", true, 9080, true, 8443));
        assertEquals(List.of("https://mcp.internal:8443/ui/"),
                UiRoutes.urls(Optional.empty(), "mcp.internal", false, 9080, true, 8443));
    }

    @Test
    void aPublicAddressIsTheOnlyUrl() {
        assertEquals(List.of("https://mcp.example.com/ui/"),
                UiRoutes.urls(Optional.of("https://mcp.example.com/"), "0.0.0.0", true, 9080, true, 8443));
    }
}
