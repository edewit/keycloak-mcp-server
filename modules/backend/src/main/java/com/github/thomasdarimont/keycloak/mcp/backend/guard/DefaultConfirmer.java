package com.github.thomasdarimont.keycloak.mcp.backend.guard;

import java.util.Optional;

import com.github.thomasdarimont.keycloak.mcp.confirm.ConfirmationRequest;
import com.github.thomasdarimont.keycloak.mcp.confirm.Confirmer;
import com.github.thomasdarimont.keycloak.mcp.confirm.Decision;

import io.vertx.core.json.JsonObject;

/**
 * The confirmer that is always there, last in the chain: asks the human through the
 * client's elicitation support and accepts only an explicit yes; without that support it
 * requires {@code confirm: true} in the arguments.
 */
public class DefaultConfirmer implements Confirmer {

    @Override
    public Decision confirm(ConfirmationRequest r) {
        if (r.prompter().available()) {
            String message = "Confirm " + r.tool().title().toLowerCase()
                    + (r.realm() != null ? " in realm '" + r.realm() + "'" : "") + "?\n" + r.tool().name() + " "
                    + new JsonObject(r.args()).encode();
            Optional<Boolean> answer = r.prompter().askYesNo(message);
            return answer.orElse(false) ? Decision.CONFIRMED : Decision.DECLINED;
        }
        return r.confirmFlag() ? Decision.CONFIRMED : Decision.CONFIRMATION_REQUIRED;
    }

    @Override
    public int order() {
        return Integer.MAX_VALUE;
    }

}
