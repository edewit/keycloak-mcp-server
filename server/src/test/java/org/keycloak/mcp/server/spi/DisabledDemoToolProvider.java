package org.keycloak.mcp.server.spi;

import java.util.List;

import org.keycloak.mcp.catalog.ToolSpec;
import org.keycloak.mcp.spi.ToolProvider;
import org.keycloak.mcp.spi.ToolProviderContext;

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
