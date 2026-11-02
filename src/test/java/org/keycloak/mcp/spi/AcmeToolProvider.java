package org.keycloak.mcp.spi;

import java.util.List;
import java.util.Map;

import org.keycloak.mcp.catalog.Category;
import org.keycloak.mcp.catalog.InputSchema;
import org.keycloak.mcp.catalog.ToolResult;
import org.keycloak.mcp.catalog.ToolSpec;

/**
 * Example third-party provider, registered via META-INF/services in src/test/resources.
 */
public class AcmeToolProvider implements ToolProvider {

    private String greeting;

    @Override
    public String id() {
        return "acme";
    }

    @Override
    public String displayName() {
        return "ACME demo";
    }

    @Override
    public String description() {
        return "Demonstrates the ToolProvider SPI.";
    }

    @Override
    public void init(ToolProviderContext context) {
        greeting = context.config().get("greeting", "default");
    }

    @Override
    public List<AccessCheck> accessChecks(ToolProviderContext context) {
        // global example: nobody may greet mallory, whichever tool is used
        return List.of(ctx -> "mallory".equals(ctx.arg("name"))
                ? AccessCheck.Decision.deny("blocked_name", "mallory is not welcome")
                : AccessCheck.Decision.allow());
    }

    @Override
    public List<ToolSpec> tools(ToolProviderContext context) {
        return List.of(ToolSpec.builder("keycloak_acme_ping")
                .title("ACME ping")
                .description("Returns the configured greeting (test extension).")
                .category(Category.REALM).read().global()
                .synonyms("acme", "ping")
                .schema(InputSchema.builder().string("name", "Who to greet"))
                .handler(call -> ToolResult.ok(Map.of("greeting", greeting, "name", call.str("name", "world"),
                        "caller", call.caller().isAnonymous() ? "anonymous" : call.caller().name())))
                .build());
    }
}
