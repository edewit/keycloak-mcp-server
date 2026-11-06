package com.github.thomasdarimont.keycloak.mcp.backend.guard;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import com.github.thomasdarimont.keycloak.mcp.access.Caller;
import com.github.thomasdarimont.keycloak.mcp.backend.Fixtures;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolSpec;
import com.github.thomasdarimont.keycloak.mcp.confirm.ConfirmationRequest;
import com.github.thomasdarimont.keycloak.mcp.confirm.Confirmer;
import com.github.thomasdarimont.keycloak.mcp.confirm.Decision;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ConfirmerChainTest {

    private static final ToolSpec DELETE = Fixtures.specs()
        .stream()
        .filter(s -> s.name().equals("keycloak_user_delete"))
        .findFirst()
        .orElseThrow();

    private static ConfirmationRequest request(boolean flag) {
        return new ConfirmationRequest(DELETE, null, "demo", Map.of("id", "1"), flag, Caller.NONE, null);
    }

    private static Confirmer ordered(int order, Decision d) {
        return new Confirmer() {
            @Override
            public Decision confirm(ConfirmationRequest r) {
                return d;
            }

            @Override
            public int order() {
                return order;
            }
        };
    }

    @Test
    void firstNonAbstainingDecisionWinsInOrder() {
        ConfirmerChain chain = new ConfirmerChain(List.of(ordered(20, Decision.CONFIRMED),
                ordered(10, Decision.ABSTAIN), ordered(15, Decision.declined("no")), new DefaultConfirmer()));
        assertEquals("no", chain.confirm(request(true)).message());
        assertEquals(Decision.Outcome.DECLINED, chain.confirm(request(true)).outcome());
    }

    @Test
    void builtInConfirmerDecidesWhenEveryoneAbstains() {
        ConfirmerChain chain = new ConfirmerChain(List.of(ordered(1, Decision.ABSTAIN), new DefaultConfirmer()));
        assertEquals(Decision.Outcome.CONFIRMED, chain.confirm(request(true)).outcome());
        assertEquals(Decision.Outcome.CONFIRMATION_REQUIRED, chain.confirm(request(false)).outcome());
    }

    @Test
    void failingConfirmerDeclines() {
        Confirmer boom = r -> {
            throw new IllegalStateException("ticket system down");
        };
        Decision d = new ConfirmerChain(List.of(boom, new DefaultConfirmer())).confirm(request(true));
        assertEquals(Decision.Outcome.DECLINED, d.outcome());
        assertEquals("Confirmation failed: ticket system down", d.message());
    }

    @Test
    void denyFallbackIgnoresTheFlag() {
        ConfirmerChain chain = new ConfirmerChain(
                List.of(new DefaultConfirmer(com.github.thomasdarimont.keycloak.mcp.config.ConfirmFallback.DENY)));
        Decision d = chain.confirm(request(true));
        assertEquals(Decision.Outcome.CONFIRMATION_REQUIRED, d.outcome());
        assertEquals(DefaultConfirmer.ELICITATION_REQUIRED, d.message());
        assertEquals(Decision.Outcome.CONFIRMED,
                new ConfirmerChain(List.of(ordered(1, Decision.CONFIRMED),
                        new DefaultConfirmer(com.github.thomasdarimont.keycloak.mcp.config.ConfirmFallback.DENY)))
                    .confirm(request(false))
                    .outcome(),
                "another confirmer (ticket, CIBA) may still confirm");
    }

}
