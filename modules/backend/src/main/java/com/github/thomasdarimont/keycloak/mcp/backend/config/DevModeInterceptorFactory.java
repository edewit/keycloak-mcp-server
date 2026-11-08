package com.github.thomasdarimont.keycloak.mcp.backend.config;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.OptionalInt;

import com.google.auto.service.AutoService;

import io.smallrye.config.ConfigSourceInterceptor;
import io.smallrye.config.ConfigSourceInterceptorContext;
import io.smallrye.config.ConfigSourceInterceptorFactory;
import io.smallrye.config.ConfigValue;

/**
 * Development mode ({@code kc-mcp.dev-mode=true}, what {@code bin/kcmcp.sh start-dev}
 * sets): when no system is configured at all, the server assumes the system
 * {@code default} at {@code http://localhost:8080}, the Keycloak of the examples, so a
 * fresh distribution starts against a local Keycloak without a line of configuration. A
 * configured system of any name switches the assumption off, as does
 * {@code kc-mcp.static-systems=false}. Below {@link DefaultTenantInterceptorFactory}, so
 * the default OIDC tenant derives from the assumed system like from a configured one.
 */
@AutoService(ConfigSourceInterceptorFactory.class)
public class DevModeInterceptorFactory implements ConfigSourceInterceptorFactory {

    public static final String DEV_MODE = "kc-mcp.dev-mode";
    public static final String DEFAULT_URL = "kc-mcp.systems.default.url";
    public static final String LOCAL_KEYCLOAK = "http://localhost:8080";

    static final int PRIORITY = DefaultTenantInterceptorFactory.PRIORITY - 50;

    @Override
    public ConfigSourceInterceptor getInterceptor(ConfigSourceInterceptorContext context) {
        return new ConfigSourceInterceptor() {
            @Override
            public ConfigValue getValue(ConfigSourceInterceptorContext ctx, String name) {
                ConfigValue value = ctx.proceed(name);
                if (!DEFAULT_URL.equals(name)
                        || (value != null && value.getValue() != null && !value.getValue().isBlank())
                        || !assumesLocalKeycloak(ctx)) {
                    return value;
                }
                return ConfigValue.builder()
                    .withName(DEFAULT_URL)
                    .withValue(LOCAL_KEYCLOAK)
                    .withRawValue(LOCAL_KEYCLOAK)
                    .withConfigSourceName("kc-mcp start-dev")
                    .withConfigSourceOrdinal(0)
                    .build();
            }

            @Override
            public Iterator<String> iterateNames(ConfigSourceInterceptorContext ctx) {
                Iterator<String> names = ctx.iterateNames();
                if (!assumesLocalKeycloak(ctx)) {
                    return names;
                }
                List<String> all = new ArrayList<>();
                names.forEachRemaining(all::add);
                if (!all.contains(DEFAULT_URL)) {
                    all.add(DEFAULT_URL);
                }
                return all.iterator();
            }
        };
    }

    /** Dev mode on, static systems in use, and no system with a url anywhere. */
    static boolean assumesLocalKeycloak(ConfigSourceInterceptorContext ctx) {
        if (!"true".equalsIgnoreCase(raw(ctx, DEV_MODE))
                || "false".equalsIgnoreCase(raw(ctx, "kc-mcp.static-systems"))) {
            return false;
        }
        Iterator<String> it = ctx.iterateNames();
        while (it.hasNext()) {
            String n = it.next();
            if (n.startsWith(DefaultTenantInterceptorFactory.SYSTEMS) && n.endsWith(".url") && raw(ctx, n) != null) {
                return false;
            }
        }
        return true;
    }

    private static String raw(ConfigSourceInterceptorContext ctx, String name) {
        ConfigValue v = ctx.proceed(name);
        return v == null || v.getValue() == null || v.getValue().isBlank() ? null : v.getValue().trim();
    }

    @Override
    public OptionalInt getPriority() {
        return OptionalInt.of(PRIORITY);
    }
}
