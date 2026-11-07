package com.github.thomasdarimont.keycloak.mcp.backend.config;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import io.smallrye.config.PropertiesConfigSource;
import io.smallrye.config.SmallRyeConfig;
import io.smallrye.config.SmallRyeConfigBuilder;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ConfigFilesSourceFactoryTest {

    @TempDir
    Path dir;

    SmallRyeConfig config(String files, Map<String, String> system, Map<String, String> defaults) {
        return new SmallRyeConfigBuilder().withSources(new ConfigFilesSourceFactory())
            .withSources(new PropertiesConfigSource(Map.of(ConfigFilesSourceFactory.PROPERTY, files), "sys", 400))
            .withSources(new PropertiesConfigSource(system, "system properties", 400))
            .withSources(new PropertiesConfigSource(defaults, "application.properties", 250))
            .build();
    }

    @Test
    void filesSitBetweenTheJarDefaultsAndTheCommandLine() throws IOException {
        // a directory with a space, as C:\Program Files or a user's folder
        Path conf = Files.createDirectories(dir.resolve("dist dir").resolve("conf"));
        Path main = Files.writeString(conf.resolve("kcmcp.properties"),
                "kc-mcp.url=http://from-file\nkc-mcp.default-realm=file\n");
        Path extra = Files.writeString(conf.resolve("extra.properties"),
                "kc-mcp.default-realm=extra\nkc-mcp.read-only=true\n");

        SmallRyeConfig c = config(main + ", " + extra, Map.of("kc-mcp.url", "http://from-command-line"),
                Map.of("kc-mcp.url", "http://default", "kc-mcp.tool-exposure", "hybrid"));

        assertEquals("http://from-command-line", c.getRawValue("kc-mcp.url"), "a system property beats the file");
        assertEquals("hybrid", c.getRawValue("kc-mcp.tool-exposure"), "defaults stay where no file speaks");
        assertEquals("true", c.getRawValue("kc-mcp.read-only"), "the file beats the defaults");
        assertTrue(c.getRawValue("kc-mcp.default-realm").equals("extra")
                || c.getRawValue("kc-mcp.default-realm").equals("file"), "both files are read");
    }

    @Test
    void aMissingFileStopsTheStart() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> config(dir.resolve("missing.properties").toString(), Map.of(), Map.of()));
        assertTrue(e.getMessage().contains("missing.properties"), e.getMessage());
    }

    @Test
    void noFilesNoSources() {
        assertEquals("http://default",
                config("", Map.of(), Map.of("kc-mcp.url", "http://default")).getRawValue("kc-mcp.url"));
    }
}
