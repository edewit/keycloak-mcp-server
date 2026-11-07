package com.github.thomasdarimont.keycloak.mcp.backend.config;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import org.eclipse.microprofile.config.spi.ConfigSource;

import com.google.auto.service.AutoService;

import io.smallrye.config.ConfigSourceContext;
import io.smallrye.config.ConfigSourceFactory;
import io.smallrye.config.ConfigValue;
import io.smallrye.config.PropertiesConfigSource;

/**
 * Loads the properties files named by {@code kc-mcp.config-files}, a comma-separated list
 * of paths: the distribution's {@code conf/kcmcp.properties} and the {@code --config}
 * files its scripts pass. Plain paths, so spaces and Windows drive letters need no
 * encoding. The first file gets ordinal {@value #ORDINAL}, every further one the next
 * number, so a later file overrides an earlier one (a {@code --config} scenario on top of
 * {@code conf/kcmcp.properties}): above the defaults in the jar's
 * {@code application.properties} (250), below {@code .env} (295), environment variables
 * (300) and system properties (400), so {@code KC_MCP_URL=...} and
 * {@code --kc-mcp.url=...} override what any file says. A path cannot contain a comma.
 * {@code quarkus.config.locations} would rank the files like the source that names them,
 * which is the system property here, and a command line option could then not override a
 * file. A listed file that does not exist stops the start.
 */
@AutoService(ConfigSourceFactory.class)
public class ConfigFilesSourceFactory implements ConfigSourceFactory {

    public static final String PROPERTY = "kc-mcp.config-files";

    public static final int ORDINAL = 275;

    /** Below {@code .env} (295) whatever the number of files. */
    static final int MAX_ORDINAL = 294;

    @Override
    public Iterable<ConfigSource> getConfigSources(ConfigSourceContext context) {
        ConfigValue value = context.getValue(PROPERTY);
        if (value == null || value.getValue() == null || value.getValue().isBlank()) {
            return List.of();
        }
        List<ConfigSource> sources = new ArrayList<>();
        int ordinal = ORDINAL;
        for (String entry : value.getValue().split(",")) {
            String name = entry.trim();
            if (name.isEmpty()) {
                continue;
            }
            Path file = Path.of(name);
            if (!Files.isRegularFile(file)) {
                throw new IllegalArgumentException(PROPERTY + ": configuration file not found: " + file);
            }
            try {
                sources.add(new PropertiesConfigSource(file.toUri().toURL(), ordinal));
                ordinal = Math.min(ordinal + 1, MAX_ORDINAL);
            }
            catch (IOException e) {
                throw new IllegalArgumentException(PROPERTY + ": cannot read " + file + ": " + e.getMessage(), e);
            }
        }
        return sources;
    }
}
