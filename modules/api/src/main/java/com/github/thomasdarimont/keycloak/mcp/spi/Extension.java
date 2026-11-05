package com.github.thomasdarimont.keycloak.mcp.spi;

import com.github.thomasdarimont.keycloak.mcp.access.AccessCheck;
import com.github.thomasdarimont.keycloak.mcp.audit.AuditListener;
import com.github.thomasdarimont.keycloak.mcp.confirm.Confirmer;
import com.github.thomasdarimont.keycloak.mcp.prompts.PromptProvider;
import com.github.thomasdarimont.keycloak.mcp.tools.ToolProvider;

/**
 * What every extension point shares: {@link ToolProvider}, {@link PromptProvider},
 * {@link AccessCheck}, {@link Confirmer} and {@link AuditListener} are extensions. The id
 * keys the configuration ({@code kc-mcp.spi.<id>.*}, {@code enabled=false} switches the
 * extension off) and must be unique per type; the order decides the sequence in which
 * extensions of one type run or are initialised.
 */
public interface Extension {

    /**
     * Unique, stable id such as {@code users} or {@code acme-tickets}. Configuration keys
     * use it in kebab-case ({@code acmeTickets} -> {@code kc-mcp.spi.acme-tickets.*}, see
     * {@link ProviderConfig#configId}). Defaults to the class name.
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
