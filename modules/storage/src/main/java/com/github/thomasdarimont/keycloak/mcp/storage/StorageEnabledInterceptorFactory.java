package com.github.thomasdarimont.keycloak.mcp.storage;

import java.util.OptionalInt;

import com.google.auto.service.AutoService;

import io.smallrye.config.ConfigSourceInterceptor;
import io.smallrye.config.ConfigSourceInterceptorContext;
import io.smallrye.config.ConfigSourceInterceptorFactory;
import io.smallrye.config.ConfigValue;
import io.smallrye.config.DefaultValuesConfigSource;
import io.smallrye.config.Priorities;

/**
 * Derives the default of {@code kc-mcp.storage.enabled} from the datasource: on when
 * {@code quarkus.datasource.jdbc.url} is configured, off otherwise, so a deployment
 * without a database runs on the static configuration alone and one with a database needs
 * no second switch. An explicit {@code kc-mcp.storage.enabled} from any source always
 * wins.
 * <p>
 * An interceptor rather than a config source factory: a factory sees the sources
 * registered before it but none that another factory contributes, and the files of
 * {@code quarkus.config.locations} (the distribution's {@code conf/}) come from such a
 * factory. The interceptor answers at lookup time, over the complete configuration. It
 * sits below SmallRye's expression interceptor, so {@code ${kc-mcp.storage.enabled}} in
 * the module's defaults reaches it, and above the sources, so it sees what they hold.
 */
@AutoService(ConfigSourceInterceptorFactory.class)
public class StorageEnabledInterceptorFactory implements ConfigSourceInterceptorFactory {

    public static final String ENABLED = "kc-mcp.storage.enabled";
    public static final String JDBC_URL = "quarkus.datasource.jdbc.url";

    /**
     * Below the expression and profile interceptors ({@code LIBRARY + 300} and
     * {@code + 200}).
     */
    static final int PRIORITY = Priorities.LIBRARY + 100;

    @Override
    public ConfigSourceInterceptor getInterceptor(ConfigSourceInterceptorContext context) {
        return new ConfigSourceInterceptor() {
            @Override
            public ConfigValue getValue(ConfigSourceInterceptorContext ctx, String name) {
                ConfigValue value = ctx.proceed(name);
                if (!ENABLED.equals(name) || (value != null && value.getValue() != null && !isMappingDefault(value))) {
                    return value;
                }
                ConfigValue url = ctx.proceed(JDBC_URL);
                boolean configured = url != null && url.getValue() != null && !url.getValue().isBlank();
                return ConfigValue.builder()
                    .withName(ENABLED)
                    .withValue(String.valueOf(configured))
                    .withRawValue(String.valueOf(configured))
                    .withConfigSourceName("kc-mcp storage defaults")
                    .withConfigSourceOrdinal(0)
                    .build();
            }
        };
    }

    /**
     * The mapping's own {@code @WithDefault("false")} lives in a source below everything
     * else; it counts as "not set", the derived value replaces it.
     */
    static boolean isMappingDefault(ConfigValue value) {
        return value.getConfigSourceOrdinal() == Integer.MIN_VALUE
                || DefaultValuesConfigSource.NAME.equals(value.getConfigSourceName());
    }

    @Override
    public OptionalInt getPriority() {
        return OptionalInt.of(PRIORITY);
    }
}
