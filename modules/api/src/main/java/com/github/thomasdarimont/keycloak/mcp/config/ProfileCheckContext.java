package com.github.thomasdarimont.keycloak.mcp.config;

import java.util.Optional;
import java.util.function.Function;

import com.github.thomasdarimont.keycloak.mcp.spi.ProviderConfig;

/**
 * What a {@link ProfileCheck} looks at.
 *
 * @param profile the deployment profile ({@code kc-mcp.profile})
 * @param callersRequired whether the MCP endpoint refuses anonymous requests
 * @param serverConfig the server's configuration; {@code null} in tests that do not need
 * it
 * @param config the check's own settings, {@code kc-mcp.spi.<spi>.<id>.*}
 * @param properties any configuration property by name ({@code quarkus.http.host}, ...),
 * blank values as absent
 */
public record ProfileCheckContext(Profile profile, boolean callersRequired, McpServerConfig serverConfig,
        ProviderConfig config, Function<String, Optional<String>> properties) {

    public ProfileCheckContext {
        profile = profile == null ? Profile.LOCAL : profile;
        properties = properties == null ? name -> Optional.empty() : properties;
    }

    public boolean shared() {
        return profile.shared();
    }

    /** A configuration property, empty when unset or blank. */
    public Optional<String> property(String name) {
        return properties.apply(name).filter(v -> !v.isBlank());
    }
}
