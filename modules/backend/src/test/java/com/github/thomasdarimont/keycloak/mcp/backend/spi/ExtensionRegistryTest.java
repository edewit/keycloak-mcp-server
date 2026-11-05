package com.github.thomasdarimont.keycloak.mcp.backend.spi;

import java.util.List;
import jakarta.inject.Inject;

import org.junit.jupiter.api.Test;

import com.github.thomasdarimont.keycloak.mcp.access.AccessCheck;
import com.github.thomasdarimont.keycloak.mcp.audit.AuditListener;
import com.github.thomasdarimont.keycloak.mcp.confirm.Confirmer;
import com.github.thomasdarimont.keycloak.mcp.prompts.PromptProvider;
import com.github.thomasdarimont.keycloak.mcp.spi.Extension;
import com.github.thomasdarimont.keycloak.mcp.spi.ExtensionRegistry;
import com.github.thomasdarimont.keycloak.mcp.spi.ProviderConfig;
import com.github.thomasdarimont.keycloak.mcp.tools.ToolProvider;

import io.quarkus.test.junit.QuarkusTest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The registry as the server wires it: every SPI goes through one place. */
@QuarkusTest
class ExtensionRegistryTest {

    @Inject
    ExtensionRegistry registry;

    @Inject
    DefaultExtensionRegistry defaults;

    @Test
    void everySpiIsServedByTheRegistry() {
        assertSame(defaults, registry);
        assertTrue(registry.extensions(Confirmer.class).stream().anyMatch(c -> c instanceof TicketConfirmer));
        assertTrue(
                registry.extensions(AuditListener.class).stream().anyMatch(l -> l instanceof RecordingAuditListener));
        assertTrue(registry.extensions(AccessCheck.class).stream().anyMatch(c -> c instanceof StandaloneDenyCheck));
        assertTrue(registry.extensions(PromptProvider.class).stream().anyMatch(p -> p.id().equals("prompts")));
        assertEquals("users", registry.extension(ToolProvider.class, "users").orElseThrow().id());
        assertTrue(registry.extension(ToolProvider.class, "nope").isEmpty());
    }

    @Test
    void extensionsAreOrderedAndIdsDefaultToTheClassName() {
        List<Confirmer> confirmers = registry.extensions(Confirmer.class);
        for (int i = 1; i < confirmers.size(); i++) {
            assertTrue(confirmers.get(i - 1).order() <= confirmers.get(i).order(), confirmers.toString());
        }
        Extension ticket = registry.extensions(Confirmer.class)
            .stream()
            .filter(c -> c instanceof TicketConfirmer)
            .findFirst()
            .orElseThrow();
        assertEquals(TicketConfirmer.class.getName(), ticket.id());
        assertEquals(ticket.id(), ticket.displayName());
        assertEquals("", ticket.description());
        assertSame(registry.extensions(Confirmer.class), registry.extensions(Confirmer.class), "cached");
        assertEquals("kc-mcp.spi.ticket.", registry.context("ticket").config().providerPrefix());
        // camelCase ids are configured in kebab-case, as Keycloak does with provider ids
        ProviderConfig camel = registry.context("acmeTicketChecker").config();
        assertEquals("kc-mcp.spi.acme-ticket-checker.", camel.providerPrefix());
        assertEquals("KC_MCP_SPI_ACME_TICKET_CHECKER_", camel.envPrefix());
        assertEquals("CHG-", camel.get("ticket-prefix", "none"));
    }
}
