package com.github.thomasdarimont.keycloak.mcp.backend.spi;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.junit.jupiter.api.Test;

import com.github.thomasdarimont.keycloak.mcp.config.McpServerConfig;
import com.github.thomasdarimont.keycloak.mcp.spi.Extension;
import com.github.thomasdarimont.keycloak.mcp.spi.ProviderConfig;

import io.smallrye.config.PropertiesConfigSource;
import io.smallrye.config.SmallRyeConfigBuilder;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ProviderSelectionTest {

    private static final String SPI = "key-vault";

    private final List<String> configured = new ArrayList<>();

    private final Extensions extensions = new Extensions(null, getClass().getClassLoader(), null);

    private static McpServerConfig config(Map<String, String> values) {
        return new SmallRyeConfigBuilder().withMapping(McpServerConfig.class)
            .withSources(new PropertiesConfigSource(values, "test", 500))
            .build()
            .getConfigMapping(McpServerConfig.class);
    }

    private final class Candidate implements Extension {
        private final String id;

        private final int order;

        private final boolean supported;

        Candidate(String id, int order, boolean supported) {
            this.id = id;
            this.order = order;
            this.supported = supported;
        }

        @Override
        public String spiName() {
            return SPI;
        }

        @Override
        public String id() {
            return id;
        }

        @Override
        public int order() {
            return order;
        }

        @Override
        public void configure(ProviderConfig config) {
            configured.add(id);
        }

        @Override
        public boolean isSupported(McpServerConfig serverConfig, ProviderConfig config) {
            return supported;
        }
    }

    private Optional<Candidate> select(List<Candidate> found, Candidate builtIn, Map<String, String> values) {
        return extensions.select(found, List.of(builtIn), SPI, "KeyVault", config(values));
    }

    @Test
    void withoutASelectionTheLowestOrderServesAndTheOthersAreLeftAlone() {
        Candidate low = new Candidate("low", 1, true);
        assertSame(low,
                select(List.of(new Candidate("high", 5, true), low), new Candidate("built-in", 0, true), Map.of())
                    .orElseThrow());
        assertEquals(List.of("low"), configured);
    }

    @Test
    void anUnsupportedCandidateIsSkippedAndTheBuiltInComesLast() {
        Candidate builtIn = new Candidate("built-in", -100, true);
        assertSame(builtIn, select(List.of(new Candidate("low", 1, false)), builtIn, Map.of()).orElseThrow());
    }

    @Test
    void theSelectionBeatsTheOrderAndReachesBuiltIns() {
        Candidate builtIn = new Candidate("file-key-vault", 0, true);
        Candidate low = new Candidate("low", 1, true);
        assertSame(builtIn,
                select(List.of(low), builtIn, Map.of("kc-mcp.spi.key-vault.provider", "file-key-vault")).orElseThrow());
        assertEquals(List.of("file-key-vault"), configured, "the one that would have won by order stays untouched");
    }

    @Test
    void aSelectionThatCannotServeStopsTheStartInsteadOfFallingBack() {
        Candidate builtIn = new Candidate("built-in", 0, true);
        IllegalStateException missing = assertThrows(IllegalStateException.class,
                () -> select(List.of(), builtIn, Map.of("kc-mcp.spi.key-vault.provider", "nope")));
        assertTrue(missing.getMessage().contains("'nope'"), missing.getMessage());
        assertThrows(IllegalStateException.class, () -> select(List.of(new Candidate("off", 1, false)), builtIn,
                Map.of("kc-mcp.spi.key-vault.provider", "off")));
    }

    @Test
    void providerAndExtensionSettingsLiveSideBySide() {
        McpServerConfig c = config(Map.of("kc-mcp.spi.key-vault.provider", "db", "kc-mcp.spi.key-vault.db.grace", "5"));
        assertEquals(Optional.of("db"), ProviderConfig.selectedProvider(SPI, c, Map.of()));
        assertEquals("5", ProviderConfig.forExtension(SPI, "db", c).get("grace", "none"));
        assertEquals(Optional.of("env"),
                ProviderConfig.selectedProvider(SPI, c, Map.of("KC_MCP_SPI_KEY_VAULT_PROVIDER", "env")));
    }

    @Test
    void aSelectionWhereEveryExtensionRunsIsRefused() {
        assertEquals(List.of("kc-mcp.spi.tools.provider"),
                Extensions.misplacedProviders(config(Map.of("kc-mcp.spi.tools.provider", "users")), Map.of()));
        assertEquals(List.of("kc-mcp.spi.confirmer.provider"),
                Extensions.misplacedProviders(config(Map.of()), Map.of("KC_MCP_SPI_CONFIRMER_PROVIDER", "built-in")));
        assertEquals(List.of(),
                Extensions.misplacedProviders(config(Map.of("kc-mcp.spi.key-vault.provider", "db")), Map.of()));
    }
}
