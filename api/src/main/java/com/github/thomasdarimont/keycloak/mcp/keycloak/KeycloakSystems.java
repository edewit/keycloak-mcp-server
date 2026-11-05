package com.github.thomasdarimont.keycloak.mcp.keycloak;

import java.util.List;
import java.util.Optional;

/**
 * The Keycloak systems this server administers ({@code ToolProviderContext.systems()}):
 * one in the usual case, several with {@code kc-mcp.systems.<name>.*}. Each system has
 * one {@link KeycloakAdmin}, connected lazily on first use.
 */
public interface KeycloakSystems {

    /**
     * Names of all configured systems: the default system first, the others alphabetical.
     *
     * @return at least one name
     */
    List<String> names();

    /**
     * Whether more than one system is configured, in which case tools take a
     * {@code system} argument.
     */
    boolean multiple();

    /**
     * Whether systems can appear at runtime (a {@link KeycloakSystemRepository} is
     * registered); the {@code system} argument is then free text instead of a closed
     * enumeration, and {@link #names()} is the current snapshot.
     */
    default boolean dynamic() {
        return false;
    }

    /**
     * Name of the system used when a call names none: the only system, the one configured
     * as {@code kc-mcp.default-system}, or the one called {@code default}; empty when
     * several systems exist and none of them is the default.
     */
    Optional<String> defaultName();

    /**
     * The admin client of a system by name.
     *
     * @param name a system name as listed by {@link #names()}
     * @return the client, or empty for an unknown name
     */
    Optional<KeycloakAdmin> find(String name);

    /**
     * The admin client of a system by name.
     *
     * @param name a system name as listed by {@link #names()}
     * @throws IllegalArgumentException for an unknown name; the message lists the known
     * ones
     */
    KeycloakAdmin get(String name);

    /**
     * The admin client of the default system.
     *
     * @throws IllegalStateException when several systems exist and none is the default
     * (see {@link #defaultName()})
     */
    KeycloakAdmin defaultAdmin();

    /** The admin clients of all systems, in the order of {@link #names()}. */
    List<KeycloakAdmin> all();

}
