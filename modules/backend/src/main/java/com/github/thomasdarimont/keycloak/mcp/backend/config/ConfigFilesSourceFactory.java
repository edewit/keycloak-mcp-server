package com.github.thomasdarimont.keycloak.mcp.backend.config;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.stream.Stream;

import org.eclipse.microprofile.config.spi.ConfigSource;

import com.google.auto.service.AutoService;

import io.smallrye.config.ConfigSourceContext;
import io.smallrye.config.ConfigSourceFactory;
import io.smallrye.config.ConfigValue;
import io.smallrye.config.PropertiesConfigSource;

/**
 * Loads the properties files named by {@code kc-mcp.config-files}, a comma-separated list
 * of paths: the distribution's {@code conf/kcmcp.conf} and the {@code --config} files its
 * scripts pass. A directory stands for its {@code *.conf} and {@code *.properties} files
 * in name order, so one file per Keycloak system under {@code conf/systems/} is loaded as
 * a whole; the content is Java properties whatever the extension. Plain paths, so spaces
 * and Windows drive letters need no encoding. All files are merged into one config
 * source, in order, a later file's value replacing an earlier one's (a {@code --config}
 * scenario on top of {@code conf/kcmcp.conf}), at ordinal {@value #ORDINAL}: above the
 * defaults in the jar's {@code application.properties} (250), below {@code .env} (295),
 * environment variables (300) and system properties (400), so
 * {@code KC_MCP_SYSTEMS_DEFAULT_URL=...} and {@code --kc-mcp.systems.default.url=...}
 * override what any file says. One source rather than one per file, because the ordinals
 * between 250 and 295 would run out after twenty files. {@code quarkus.config.locations}
 * would rank the files like the source that names them, which is the system property
 * here, and a command line option could then not override a file. A listed path that does
 * not exist stops the start; a path cannot contain a comma.
 */
@AutoService(ConfigSourceFactory.class)
public class ConfigFilesSourceFactory implements ConfigSourceFactory {

    public static final String PROPERTY = "kc-mcp.config-files";

    public static final int ORDINAL = 275;

    @Override
    public Iterable<ConfigSource> getConfigSources(ConfigSourceContext context) {
        ConfigValue value = context.getValue(PROPERTY);
        if (value == null || value.getValue() == null || value.getValue().isBlank()) {
            return List.of();
        }
        Map<String, String> merged = new LinkedHashMap<>();
        List<String> names = new ArrayList<>();
        for (String entry : value.getValue().split(",")) {
            String name = entry.trim();
            if (name.isEmpty()) {
                continue;
            }
            for (Path file : files(Path.of(name))) {
                Properties properties = new Properties();
                try (InputStream in = Files.newInputStream(file)) {
                    properties.load(in);
                }
                catch (IOException e) {
                    throw new IllegalArgumentException(PROPERTY + ": cannot read " + file + ": " + e.getMessage(), e);
                }
                for (String key : properties.stringPropertyNames()) {
                    merged.put(key, properties.getProperty(key));
                }
                names.add(file.toString());
            }
        }
        if (names.isEmpty()) {
            return List.of();
        }
        return List.of(new PropertiesConfigSource(merged, PROPERTY + " [" + String.join(", ", names) + "]", ORDINAL));
    }

    /** {@code .conf} as Keycloak names them, or {@code .properties}. */
    static boolean isConfigFile(String name) {
        return name.endsWith(".conf") || name.endsWith(".properties");
    }

    /**
     * The file itself, or the {@code *.conf} and {@code *.properties} files of a
     * directory in name order.
     */
    static List<Path> files(Path path) {
        if (Files.isRegularFile(path)) {
            return List.of(path);
        }
        if (Files.isDirectory(path)) {
            try (Stream<Path> entries = Files.list(path)) {
                return entries.filter(p -> Files.isRegularFile(p) && isConfigFile(p.getFileName().toString()))
                    .sorted(Comparator.comparing(p -> p.getFileName().toString()))
                    .toList();
            }
            catch (IOException e) {
                throw new IllegalArgumentException(PROPERTY + ": cannot list " + path + ": " + e.getMessage(), e);
            }
        }
        throw new IllegalArgumentException(PROPERTY + ": configuration file not found: " + path);
    }
}
