package com.github.thomasdarimont.keycloak.mcp.storage;

import java.util.List;
import java.util.Map;

import org.eclipse.microprofile.config.spi.ConfigSource;

import com.google.auto.service.AutoService;

import io.smallrye.config.ConfigSourceContext;
import io.smallrye.config.ConfigSourceFactory;
import io.smallrye.config.ConfigValue;
import io.smallrye.config.PropertiesConfigSource;

/**
 * Derives the default of {@code kc-mcp.storage.enabled} from the datasource: on when
 * {@code quarkus.datasource.jdbc.url} is configured, off otherwise, so a deployment
 * without a database runs on the static configuration alone and one with a database needs
 * no second switch. The derived value sits below every file and environment source, so an
 * explicit {@code kc-mcp.storage.enabled} always wins.
 */
@AutoService(ConfigSourceFactory.class)
public class StorageConfigSourceFactory implements ConfigSourceFactory {

    public static final String ENABLED = "kc-mcp.storage.enabled";
    public static final String JDBC_URL = "quarkus.datasource.jdbc.url";

    /**
     * Above the default values of the mapping, below
     * {@code microprofile-config.properties}.
     */
    static final int ORDINAL = 90;

    @Override
    public Iterable<ConfigSource> getConfigSources(ConfigSourceContext context) {
        ConfigValue url = context.getValue(JDBC_URL);
        boolean configured = url != null && url.getValue() != null && !url.getValue().isBlank();
        return List.of(new PropertiesConfigSource(Map.of(ENABLED, String.valueOf(configured)),
                "kc-mcp storage defaults", ORDINAL));
    }
}
