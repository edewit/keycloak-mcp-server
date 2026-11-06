package com.acme.keycloak.mcp;

import java.util.regex.Pattern;

import com.github.thomasdarimont.keycloak.mcp.confirm.ConfirmationRequest;
import com.github.thomasdarimont.keycloak.mcp.confirm.Confirmer;
import com.github.thomasdarimont.keycloak.mcp.confirm.Decision;
import com.google.auto.service.AutoService;

/**
 * Extension point {@link Confirmer}: runs before the built-in confirmation of destructive
 * tools. A valid change ticket confirms the offboarding without a prompt, a missing or
 * malformed one declines it; other tools are left to the next confirmer
 * ({@link Decision#abstain()}). Ticket pattern: {@code kc-mcp.spi.acme-ticket-confirmer.pattern}.
 */
@AutoService(Confirmer.class)
public class TicketConfirmer implements Confirmer {

    static final String TOOL = "keycloak_acme_user_offboard";
    static final Pattern DEFAULT_PATTERN = Pattern.compile("ACME-\\d+");

    private final Pattern pattern;

    public TicketConfirmer() {
        this(DEFAULT_PATTERN);
    }

    TicketConfirmer(Pattern pattern) {
        this.pattern = pattern;
    }

    @Override
    public String id() {
        return "acme-ticket-confirmer";
    }

    @Override
    public Decision confirm(ConfirmationRequest r) {
        if (!TOOL.equals(r.tool().name())) {
            return Decision.abstain();
        }
        Object ticket = r.args().get("ticket");
        if (ticket != null && pattern.matcher(String.valueOf(ticket)).matches()) {
            return Decision.confirmed();
        }
        return Decision.declined("Offboarding needs an open change ticket: pass ticket=ACME-<number>.");
    }
}
