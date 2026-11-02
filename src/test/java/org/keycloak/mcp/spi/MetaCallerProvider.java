package org.keycloak.mcp.spi;

import java.util.LinkedHashSet;
import java.util.Set;

import jakarta.annotation.Priority;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Alternative;

import io.quarkiverse.mcp.server.FeatureManager.FeatureArguments;
import io.vertx.core.json.JsonObject;

/**
 * Test-only caller source: the MCP client names the caller in {@code _meta} of the tools/call request
 * ({@code kc-mcp/test-caller}, optional {@code kc-mcp/test-caller-realm}, {@code kc-mcp/test-caller-roles} csv).
 */
@Alternative
@Priority(1)
@ApplicationScoped
public class MetaCallerProvider implements CallerProvider {

    public static final String CALLER = "kc-mcp/test-caller";
    public static final String REALM = "kc-mcp/test-caller-realm";
    public static final String ROLES = "kc-mcp/test-caller-roles";

    @Override
    public Caller current(FeatureArguments args) {
        JsonObject meta = args.meta() == null ? new JsonObject() : args.meta().asJsonObject();
        String name = meta.getString(CALLER);
        if (name == null || name.isBlank()) {
            return Caller.NONE;
        }
        Set<String> roles = new LinkedHashSet<>();
        String csv = meta.getString(ROLES);
        if (csv != null) {
            for (String r : csv.split(",")) {
                if (!r.isBlank()) {
                    roles.add(r.trim());
                }
            }
        }
        return Caller.of(name, name, meta.getString(REALM), roles);
    }
}
