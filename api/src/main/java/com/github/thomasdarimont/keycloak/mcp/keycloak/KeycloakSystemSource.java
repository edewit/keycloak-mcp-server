package com.github.thomasdarimont.keycloak.mcp.keycloak;

import java.util.List;
import java.util.Optional;

import com.github.thomasdarimont.keycloak.mcp.spi.Extension;

/**
 * Supplies Keycloak systems at runtime, next to the ones in the static configuration: a
 * tenant registry, a database, a discovery call. Registered like any other extension
 * ({@code @AutoService(KeycloakSystemSource.class)} or a CDI bean). The server asks a
 * source on every lookup and caches the admin client per system name; a system whose
 * settings change is reconnected, one the source no longer knows is dropped. Sources
 * should cache what is expensive to compute. A system outside
 * {@code kc-mcp.allowed-hosts} is refused and logged, it does not stop the server.
 */
public interface KeycloakSystemSource extends Extension {

    /** The names of the systems this source currently knows. */
    List<String> names();

    /** A system by name, empty when this source does not know it. */
    Optional<KeycloakSystem> find(String name);
}
