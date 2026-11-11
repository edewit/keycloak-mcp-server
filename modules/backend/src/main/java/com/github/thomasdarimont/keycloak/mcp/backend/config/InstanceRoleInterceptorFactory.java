package com.github.thomasdarimont.keycloak.mcp.backend.config;

import java.util.OptionalInt;

import com.github.thomasdarimont.keycloak.mcp.config.InstanceRole;
import com.google.auto.service.AutoService;

import io.smallrye.config.ConfigSourceInterceptor;
import io.smallrye.config.ConfigSourceInterceptorContext;
import io.smallrye.config.ConfigSourceInterceptorFactory;
import io.smallrye.config.ConfigValue;
import io.smallrye.config.DefaultValuesConfigSource;
import io.smallrye.config.Priorities;

/**
 * Derives the endpoint switches from {@code kc-mcp.instance-role}:
 * <ul>
 * <li>{@code mcp}: {@code kc-mcp.admin.enabled} and {@code kc-mcp.ui.enabled} default to
 * {@code false}, also over what {@code start-dev} assumes;</li>
 * <li>{@code admin}: {@code kc-mcp.mcp.enabled} defaults to {@code false},
 * {@code kc-mcp.admin.enabled} to {@code true};</li>
 * <li>{@code all}: nothing changes.</li>
 * </ul>
 * A value set in a source (ordinal above 0) is left as it is; one that contradicts the
 * role stops the start ({@code ProfileChecks}), so a role is never silently overridden.
 * Above {@link DevModeInterceptorFactory}, so the role decides over its assumed UI.
 */
@AutoService(ConfigSourceInterceptorFactory.class)
public class InstanceRoleInterceptorFactory implements ConfigSourceInterceptorFactory {

    public static final String ROLE = "kc-mcp.instance-role";
    public static final String MCP_ENABLED = "kc-mcp.mcp.enabled";
    public static final String ADMIN_ENABLED = "kc-mcp.admin.enabled";
    public static final String UI_ENABLED = "kc-mcp.ui.enabled";

    static final int PRIORITY = Priorities.LIBRARY + 120;

    @Override
    public ConfigSourceInterceptor getInterceptor(ConfigSourceInterceptorContext context) {
        return new ConfigSourceInterceptor() {
            @Override
            public ConfigValue getValue(ConfigSourceInterceptorContext ctx, String name) {
                ConfigValue value = ctx.proceed(name);
                if (!MCP_ENABLED.equals(name) && !ADMIN_ENABLED.equals(name) && !UI_ENABLED.equals(name)
                        || isExplicit(value)) {
                    return value;
                }
                InstanceRole role = role(ctx);
                String derived = switch (role) {
                    case ALL -> null;
                    case MCP -> MCP_ENABLED.equals(name) ? null : "false";
                    case ADMIN -> MCP_ENABLED.equals(name) ? "false" : ADMIN_ENABLED.equals(name) ? "true" : null;
                };
                return derived == null ? value : derived(name, derived, role);
            }
        };
    }

    /** The configured role; an unknown value is left to the config mapping to report. */
    static InstanceRole role(ConfigSourceInterceptorContext ctx) {
        ConfigValue v = ctx.proceed(ROLE);
        if (v == null || v.getValue() == null || v.getValue().isBlank()) {
            return InstanceRole.ALL;
        }
        try {
            return InstanceRole.parse(v.getValue());
        }
        catch (IllegalArgumentException e) {
            return InstanceRole.ALL;
        }
    }

    /**
     * Set in a real source: neither a default of the config mapping nor a value another
     * interceptor assumed (ordinal 0).
     */
    static boolean isExplicit(ConfigValue v) {
        return v != null && v.getValue() != null && !v.getValue().isBlank() && v.getConfigSourceOrdinal() > 0
                && !DefaultValuesConfigSource.NAME.equals(v.getConfigSourceName());
    }

    private static ConfigValue derived(String name, String value, InstanceRole role) {
        return ConfigValue.builder()
            .withName(name)
            .withValue(value)
            .withRawValue(value)
            .withConfigSourceName("kc-mcp instance-role " + role.id())
            .withConfigSourceOrdinal(0)
            .build();
    }

    @Override
    public OptionalInt getPriority() {
        return OptionalInt.of(PRIORITY);
    }
}
