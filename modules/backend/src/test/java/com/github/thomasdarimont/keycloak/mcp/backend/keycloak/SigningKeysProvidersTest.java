package com.github.thomasdarimont.keycloak.mcp.backend.keycloak;

import java.util.Map;

import org.junit.jupiter.api.Test;

import com.github.thomasdarimont.keycloak.mcp.backend.spi.Extensions;
import com.github.thomasdarimont.keycloak.mcp.config.McpServerConfig;

import io.smallrye.config.PropertiesConfigSource;
import io.smallrye.config.SmallRyeConfigBuilder;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class SigningKeysProvidersTest {

    private static McpServerConfig config(Map<String, String> values) {
        return new SmallRyeConfigBuilder().withMapping(McpServerConfig.class)
            .withSources(new PropertiesConfigSource(values, "test", 500))
            .build()
            .getConfigMapping(McpServerConfig.class);
    }

    private final Extensions extensions = new Extensions(null, getClass().getClassLoader(), null);

    @Test
    void theBuiltInsServeByDefault() {
        assertEquals("file", SigningKeys.vault(config(Map.of()), extensions).id());
        assertEquals("default", SigningKeys.generator(config(Map.of()), extensions).id());
    }

    @Test
    void aSwitchedOffBuiltInIsNotUsedAnyway() {
        assertThrows(IllegalStateException.class,
                () -> SigningKeys.vault(config(Map.of("kc-mcp.spi.key-vault.file.enabled", "false")), extensions));
        assertThrows(IllegalStateException.class, () -> SigningKeys
            .generator(config(Map.of("kc-mcp.spi.key-generator.default.enabled", "false")), extensions));
    }
}
