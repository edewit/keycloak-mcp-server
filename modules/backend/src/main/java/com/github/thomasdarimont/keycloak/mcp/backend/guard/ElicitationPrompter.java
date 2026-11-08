package com.github.thomasdarimont.keycloak.mcp.backend.guard;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.Base64;
import java.util.Optional;

import org.jboss.logging.Logger;

import com.github.thomasdarimont.keycloak.mcp.confirm.Prompter;

import io.quarkiverse.mcp.server.Elicitation;
import io.quarkiverse.mcp.server.ElicitationRequest;
import io.quarkiverse.mcp.server.ElicitationRequest.BooleanSchema;
import io.quarkiverse.mcp.server.ElicitationResponse;

/**
 * {@link Prompter} over the MCP connection's form-mode elicitation. A client on a
 * stateless protocol version cannot be asked in the middle of a request: there the call
 * ends with an {@code input_required} result (an
 * {@link io.quarkiverse.mcp.server.InputRequiredException}) and the client repeats it
 * with the answer.
 */
final class ElicitationPrompter implements Prompter {

    private static final Logger LOG = Logger.getLogger(ElicitationPrompter.class);

    private static final String INPUT_KEY = "confirm";

    private final Elicitation elicitation;

    private final Duration timeout;

    ElicitationPrompter(Elicitation elicitation, Duration timeout) {
        this.elicitation = elicitation;
        this.timeout = timeout;
    }

    static Prompter of(Elicitation elicitation, Duration timeout) {
        return elicitation == null ? Prompter.NONE : new ElicitationPrompter(elicitation, timeout);
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
        if (!elicitation.isServerInitiatedRequestSupported()) {
            return askAcrossRetry(message);
        }
        try {
            return answer(request(message).sendAndAwait());
        }
        catch (RuntimeException e) {
            LOG.warnf("Elicitation failed: %s", e.toString());
            return Optional.empty();
        }
    }

    /**
     * The request state ties an answer to the question: an answer that comes back with a
     * call other than the one the user was shown is not taken, the user is asked again.
     */
    private Optional<Boolean> askAcrossRetry(String message) {
        String state = fingerprint(message);
        if (elicitation.inputResponses().has(INPUT_KEY) && state.equals(elicitation.requestState())) {
            return answer(elicitation.inputResponses().getElicitationResponse(INPUT_KEY));
        }
        throw elicitation.inputRequired()
            .addElicitationRequest(INPUT_KEY, request(message))
            .setRequestState(state)
            .build();
    }

    private ElicitationRequest request(String message) {
        return elicitation.requestBuilder()
            .setMessage(message)
            .addSchemaProperty("confirm", new BooleanSchema("Confirm", "Proceed", true, true))
            .setTimeout(timeout)
            .build();
    }

    private static Optional<Boolean> answer(ElicitationResponse response) {
        if (!response.actionAccepted()) {
            return Optional.empty();
        }
        return Optional.of(Boolean.TRUE.equals(response.content().getBoolean("confirm")));
    }

    private static String fingerprint(String message) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(message.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        }
        catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

}
