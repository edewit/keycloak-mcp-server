package com.github.thomasdarimont.keycloak.mcp.server.spi;

import java.util.List;

import com.github.thomasdarimont.keycloak.mcp.catalog.ToolSpec;
import com.github.thomasdarimont.keycloak.mcp.tools.ToolProvider;
import com.github.thomasdarimont.keycloak.mcp.tools.ToolProviderContext;
import com.google.auto.service.AutoService;

/** Disabled through kc-mcp.spi.disabled-demo.enabled=false; must never be initialised. */
@AutoService(ToolProvider.class)
public class DisabledDemoToolProvider implements ToolProvider {

    @Override
    public String id() {
        return "disabled-demo";
    }

    @Override
    public void init(ToolProviderContext context) {
        throw new IllegalStateException("disabled provider must not be initialised");
    }

    @Override
    public List<ToolSpec> tools(ToolProviderContext context) {
        throw new IllegalStateException("disabled provider must not be asked for tools");
    }
}
