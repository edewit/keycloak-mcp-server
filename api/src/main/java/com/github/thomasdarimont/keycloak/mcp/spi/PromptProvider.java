package com.github.thomasdarimont.keycloak.mcp.spi;

import java.util.List;

import com.github.thomasdarimont.keycloak.mcp.catalog.PromptSpec;

/**
 * Contributes {@link PromptSpec}s, the task recipes a user can pick in their MCP client.
 * Discovered like {@link ToolProvider}s: {@code @AutoService(PromptProvider.class)} (jars
 * in {@code providers/} included) or a CDI bean; {@code kc-mcp.spi.<id>.enabled=false}
 * switches a provider off. Prompts whose tools are all disabled on this server are not
 * registered.
 */
public interface PromptProvider {

    /** Unique, stable id such as {@code prompts} or {@code acme-recipes}. */
    String id();

    List<PromptSpec> prompts(ToolProviderContext context);

}
