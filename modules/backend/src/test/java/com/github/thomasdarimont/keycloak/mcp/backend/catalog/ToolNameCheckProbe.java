package com.github.thomasdarimont.keycloak.mcp.backend.catalog;

import java.util.List;
import java.util.Map;

/** Opens {@link ToolNameCheck}'s package-private logic to tests of other packages. */
public final class ToolNameCheckProbe {

    private ToolNameCheckProbe() {
    }

    public static List<String> problems(ToolCatalog catalog, Map<String, List<String>> names) {
        return ToolNameCheck.problems(catalog, names);
    }
}
