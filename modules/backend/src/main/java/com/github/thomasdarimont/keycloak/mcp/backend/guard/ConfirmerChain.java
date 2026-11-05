package com.github.thomasdarimont.keycloak.mcp.backend.guard;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Typed;
import jakarta.inject.Inject;

import org.jboss.logging.Logger;

import com.github.thomasdarimont.keycloak.mcp.confirm.ConfirmationRequest;
import com.github.thomasdarimont.keycloak.mcp.confirm.Confirmer;
import com.github.thomasdarimont.keycloak.mcp.confirm.Decision;
import com.github.thomasdarimont.keycloak.mcp.spi.ExtensionRegistry;

/**
 * Runs the registered {@link Confirmer}s (ServiceLoader and CDI, by
 * {@link Confirmer#order()}) and the built-in {@link DefaultConfirmer} last; the first
 * decision that is not {@code ABSTAIN} wins. A confirmer that throws is logged and
 * treated as DECLINED.
 */
@ApplicationScoped
@Typed(ConfirmerChain.class)
public class ConfirmerChain implements Confirmer {

    private static final Logger LOG = Logger.getLogger(ConfirmerChain.class);

    private final List<Confirmer> chain;

    @Inject
    public ConfirmerChain(ExtensionRegistry registry) {
        List<Confirmer> all = new ArrayList<>(registry.extensions(Confirmer.class));
        for (Confirmer c : all) {
            LOG.infof("Confirmer '%s' registered (%s, order %d)", c.id(), c.getClass().getName(), c.order());
        }
        all.add(new DefaultConfirmer());
        all.sort(Comparator.comparingInt(Confirmer::order));
        this.chain = List.copyOf(all);
    }

    /** Explicit chain, the built-in confirmer is not added. */
    public ConfirmerChain(List<Confirmer> confirmers) {
        List<Confirmer> all = new ArrayList<>(confirmers);
        all.sort(Comparator.comparingInt(Confirmer::order));
        this.chain = List.copyOf(all);
    }

    public List<Confirmer> confirmers() {
        return chain;
    }

    @Override
    public Decision confirm(ConfirmationRequest request) {
        for (Confirmer c : chain) {
            Decision d;
            try {
                d = c.confirm(request);
            }
            catch (RuntimeException e) {
                LOG.warnf(e, "Confirmer %s failed for %s", c.getClass().getName(), request.tool().name());
                return Decision.declined("Confirmation failed: " + e.getMessage());
            }
            if (d != null && d.outcome() != Decision.Outcome.ABSTAIN) {
                return d;
            }
        }
        return Decision.CONFIRMATION_REQUIRED;
    }

}
