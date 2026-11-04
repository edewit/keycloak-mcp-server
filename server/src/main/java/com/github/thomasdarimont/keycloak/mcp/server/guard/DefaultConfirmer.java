package com.github.thomasdarimont.keycloak.mcp.server.guard;

import java.time.Duration;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import org.jboss.logging.Logger;

import com.github.thomasdarimont.keycloak.mcp.catalog.ToolSpec;
import com.github.thomasdarimont.keycloak.mcp.config.McpServerConfig;

import io.quarkiverse.mcp.server.Elicitation;
import io.quarkiverse.mcp.server.ElicitationRequest.BooleanSchema;
import io.quarkiverse.mcp.server.ElicitationResponse;
import io.vertx.core.json.JsonObject;

/**
 * 1. If the client supports form-mode elicitation, ask the human and accept only an
 * explicit ACCEPT + true. 2. Otherwise require {@code confirm: true} in the arguments.
 */
@ApplicationScoped
public class DefaultConfirmer implements Confirmer {

    private static final Logger LOG = Logger.getLogger(DefaultConfirmer.class);

    private final Duration timeout;

    @Inject
    public DefaultConfirmer(McpServerConfig config) {
        this(Duration.ofSeconds(config.confirmTimeoutSeconds()));
    }

    public DefaultConfirmer(Duration timeout) {
        this.timeout = timeout;
    }

    @Override
    public Decision confirm(ToolSpec spec, String realm, JsonObject args, boolean confirmFlag, InvocationContext ctx) {
        Elicitation elicitation = ctx.elicitation();
        boolean canElicit = false;
        if (elicitation != null) {
            try {
                canElicit = elicitation.isFormModeSupported();
            }
            catch (RuntimeException e) {
                canElicit = false;
            }
        }
        if (canElicit) {
            return elicit(elicitation, spec, realm, args);
        }
        return confirmFlag ? Decision.CONFIRMED : Decision.CONFIRMATION_REQUIRED;
    }

    private Decision elicit(Elicitation elicitation, ToolSpec spec, String realm, JsonObject args) {
        String message = "Confirm " + spec.title().toLowerCase() + (realm != null ? " in realm '" + realm + "'" : "")
                + "?\n" + spec.name() + " " + args.encode();
        try {
            ElicitationResponse response = elicitation.requestBuilder()
                .setMessage(message)
                .addSchemaProperty("confirm", new BooleanSchema("Confirm", "Proceed with " + spec.name(), false, true))
                .setTimeout(timeout)
                .build()
                .sendAndAwait();
            if (!response.actionAccepted()) {
                return Decision.DECLINED;
            }
            Boolean yes = response.content().getBoolean("confirm");
            return Boolean.TRUE.equals(yes) ? Decision.CONFIRMED : Decision.DECLINED;
        }
        catch (RuntimeException e) {
            LOG.warnf("Elicitation for %s failed: %s", spec.name(), e.toString());
            return Decision.DECLINED;
        }
    }
}
