package com.github.thomasdarimont.keycloak.mcp.server.guard;

import java.time.Duration;
import java.util.Optional;

import org.jboss.logging.Logger;

import com.github.thomasdarimont.keycloak.mcp.confirm.Confirmer;

import io.quarkiverse.mcp.server.Elicitation;
import io.quarkiverse.mcp.server.ElicitationRequest.BooleanSchema;
import io.quarkiverse.mcp.server.ElicitationResponse;

/** {@link Confirmer.Prompter} over the MCP connection's form-mode elicitation. */
final class ElicitationPrompter implements Confirmer.Prompter {

    private static final Logger LOG = Logger.getLogger(ElicitationPrompter.class);

    private final Elicitation elicitation;

    private final Duration timeout;

    ElicitationPrompter(Elicitation elicitation, Duration timeout) {
        this.elicitation = elicitation;
        this.timeout = timeout;
    }

    static Confirmer.Prompter of(Elicitation elicitation, Duration timeout) {
        return elicitation == null ? Confirmer.Prompter.NONE : new ElicitationPrompter(elicitation, timeout);
    }

    @Override
    public boolean available() {
        try {
            return elicitation.isFormModeSupported();
        }
        catch (RuntimeException e) {
            return false;
        }
    }

    @Override
    public Optional<Boolean> askYesNo(String message) {
        try {
            ElicitationResponse response = elicitation.requestBuilder()
                .setMessage(message)
                .addSchemaProperty("confirm", new BooleanSchema("Confirm", "Proceed", false, true))
                .setTimeout(timeout)
                .build()
                .sendAndAwait();
            if (!response.actionAccepted()) {
                return Optional.empty();
            }
            return Optional.of(Boolean.TRUE.equals(response.content().getBoolean("confirm")));
        }
        catch (RuntimeException e) {
            LOG.warnf("Elicitation failed: %s", e.toString());
            return Optional.empty();
        }
    }

}
