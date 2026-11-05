package com.github.thomasdarimont.keycloak.mcp.spi;

/**
 * What every extension point shares: {@link ToolProvider}, {@link PromptProvider},
 * {@link AccessCheck}, {@link Confirmer} and {@link AuditListener} are extensions. The id
 * keys the configuration ({@code kc-mcp.spi.<id>.*}, {@code enabled=false} switches the
 * extension off) and must be unique per type; the order decides the sequence in which
 * extensions of one type run or are initialised.
 */
public interface Extension {

    /**
     * Unique, stable id such as {@code users} or {@code acme-tickets}. Defaults to the
     * class name, which is fine for extensions that are never configured.
     */
    default String id() {
        return getClass().getName();
    }

    /** Human readable name, e.g. "User management". Defaults to the id. */
    default String displayName() {
        return id();
    }

    /** One or two sentences on what the extension does. */
    default String description() {
        return "";
    }

    /** Lower first; ties are broken by id. */
    default int order() {
        return 0;
    }
}
