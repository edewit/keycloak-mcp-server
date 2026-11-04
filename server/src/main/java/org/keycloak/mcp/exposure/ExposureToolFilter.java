package org.keycloak.mcp.exposure;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import org.keycloak.mcp.catalog.ToolCatalog;
import org.keycloak.mcp.guard.AccessPolicy;

import io.quarkiverse.mcp.server.FilterContext;
import io.quarkiverse.mcp.server.McpMethod;
import io.quarkiverse.mcp.server.ToolFilter;
import io.quarkiverse.mcp.server.ToolManager.ToolInfo;

/**
 * Hides tools from {@code tools/list} according to the {@link ExposurePolicy} but keeps
 * every registered tool callable, so a model that guesses {@code keycloak_user_search} in
 * lazy mode still succeeds. Security (READ_ONLY, ALLOWED_REALMS) lives in the invoker,
 * never here.
 */
@ApplicationScoped
public class ExposureToolFilter implements ToolFilter {

    @Inject
    ExposurePolicy policy;
    @Inject
    AccessPolicy access;
    @Inject
    ToolCatalog catalog;

    @Override
    public boolean test(ToolInfo tool, FilterContext context) {
        if (context.method() != McpMethod.TOOLS_LIST) {
            return true;
        }
        if (!policy.listed(tool.name(), context.connection() == null ? null : context.connection().id())) {
            return false;
        }
        // roles as currently known; never blocks (ToolFilter contract)
        return catalog.get(tool.name()).map(access::visible).orElse(true);
    }
}
