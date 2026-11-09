package com.acme.keycloak.mcp;

import java.util.List;
import java.util.Optional;

import com.github.thomasdarimont.keycloak.mcp.config.ProfileCheck;
import com.github.thomasdarimont.keycloak.mcp.config.ProfileCheckContext;
import com.google.auto.service.AutoService;

/**
 * Extension point {@link ProfileCheck}: the {@link JsonLinesAuditListener} writes the
 * audit trail to a file, so on a shared server that file must be named explicitly and
 * must not live in a temporary directory that the system cleans up. In profile
 * {@code local} the same findings are only warnings.
 */
@AutoService(ProfileCheck.class)
public class AuditFileProfileCheck implements ProfileCheck {

    static final String FILE = "kc-mcp.spi.audit-listener.acme-audit.file";

    @Override
    public String id() {
        return "acme-audit-file-check";
    }

    @Override
    public List<String> problems(ProfileCheckContext ctx) {
        return ctx.shared() ? findings(ctx) : List.of();
    }

    @Override
    public List<String> warnings(ProfileCheckContext ctx) {
        return ctx.shared() ? List.of() : findings(ctx);
    }

    private static List<String> findings(ProfileCheckContext ctx) {
        Optional<String> file = ctx.property(FILE);
        if (file.isEmpty()) {
            return List.of("the ACME audit trail goes to ./acme-audit.jsonl next to the server; set " + FILE
                    + " (env KC_MCP_SPI_AUDIT_LISTENER_ACME_AUDIT_FILE) to a durable location");
        }
        String f = file.get();
        if (f.startsWith("/tmp/") || f.startsWith("/var/tmp/")) {
            return List.of("the ACME audit trail goes to " + f + ", a temporary directory the system may clean up; set "
                    + FILE + " to a durable location");
        }
        return List.of();
    }
}
