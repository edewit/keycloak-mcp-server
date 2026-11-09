package com.github.thomasdarimont.keycloak.mcp.backend.guard;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Typed;
import jakarta.inject.Inject;

import org.jboss.logging.Logger;

import com.github.thomasdarimont.keycloak.mcp.backend.metrics.KcMcpMetrics;
import com.github.thomasdarimont.keycloak.mcp.config.McpServerConfig;
import com.github.thomasdarimont.keycloak.mcp.confirm.ConfirmationRequest;
import com.github.thomasdarimont.keycloak.mcp.confirm.Confirmer;
import com.github.thomasdarimont.keycloak.mcp.confirm.Decision;
import com.github.thomasdarimont.keycloak.mcp.spi.ExtensionRegistry;

import io.quarkiverse.mcp.server.InputRequiredException;

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
    private KcMcpMetrics metrics = KcMcpMetrics.noop();

    @Inject
    public ConfirmerChain(ExtensionRegistry registry, McpServerConfig config, KcMcpMetrics metrics) {
        this(registry, config);
        this.metrics = metrics;
    }

    public ConfirmerChain(ExtensionRegistry registry, McpServerConfig config) {
        List<Confirmer> all = new ArrayList<>(registry.extensions(Confirmer.class));
        for (Confirmer c : all) {
            LOG.infof("Confirmer '%s' registered (%s, order %d)", c.id(), c.getClass().getName(), c.order());
        }
        all.add(new DefaultConfirmer(config.effectiveConfirmFallback()));
        all.sort(Comparator.comparingInt(Confirmer::order));
        this.chain = List.copyOf(all);
    }

    /** Explicit chain, the built-in confirmer is not added. */
    public ConfirmerChain(List<Confirmer> confirmers) {
        List<Confirmer> all = new ArrayList<>(confirmers);
        all.sort(Comparator.comparingInt(Confirmer::order));
        this.chain = List.copyOf(all);
    }

    /** Where the decisions are counted (tests, embedding). */
    public ConfirmerChain metrics(KcMcpMetrics metrics) {
        this.metrics = metrics == null ? KcMcpMetrics.noop() : metrics;
        return this;
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
            catch (InputRequiredException e) {
                throw e; // the question to the user, not a failure: the client repeats
                         // the call with the answer
            }
            catch (RuntimeException e) {
                LOG.warnf(e, "Confirmer %s failed for %s", c.getClass().getName(), request.tool().name());
                metrics.confirmation(c.id(), "failed", request.tool().name());
                return Decision.declined("Confirmation failed: " + e.getMessage());
            }
            if (d != null && d.outcome() != Decision.Outcome.ABSTAIN) {
                metrics.confirmation(c.id(), d.outcome().name().toLowerCase(), request.tool().name());
                return d;
            }
        }
        metrics.confirmation("none", "confirmation_required", request.tool().name());
        return Decision.CONFIRMATION_REQUIRED;
    }

}
