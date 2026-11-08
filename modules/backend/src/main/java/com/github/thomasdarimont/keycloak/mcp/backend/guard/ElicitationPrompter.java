package com.github.thomasdarimont.keycloak.mcp.backend.guard;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;
import java.util.stream.Collectors;

import org.jboss.logging.Logger;

import com.github.thomasdarimont.keycloak.mcp.access.Caller;
import com.github.thomasdarimont.keycloak.mcp.confirm.Prompter;

import io.quarkiverse.mcp.server.Elicitation;
import io.quarkiverse.mcp.server.ElicitationRequest;
import io.quarkiverse.mcp.server.ElicitationRequest.BooleanSchema;
import io.quarkiverse.mcp.server.ElicitationResponse;
import io.vertx.core.json.DecodeException;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

/**
 * {@link Prompter} over the MCP connection's form-mode elicitation. A client on a
 * stateless protocol version cannot be asked in the middle of a request: there the call
 * ends with an {@code input_required} result (an
 * {@link io.quarkiverse.mcp.server.InputRequiredException}) and the client repeats it
 * with the answer.
 */
final class ElicitationPrompter implements Prompter {

    private static final Logger LOG = Logger.getLogger(ElicitationPrompter.class);

    private static final String INPUT_KEY_PREFIX = "confirm-";

    private final Elicitation elicitation;

    private final Duration timeout;

    private final String operation;

    /** One prompter serves one request: questions are numbered in the order asked. */
    private int asked;

    private JsonObject answers;

    private boolean bound;

    ElicitationPrompter(Elicitation elicitation, Duration timeout, String operation) {
        this.elicitation = elicitation;
        this.timeout = timeout;
        this.operation = operation;
    }

    /** For asking whether the client can be asked. */
    static Prompter of(Elicitation elicitation, Duration timeout) {
        return of(elicitation, timeout, "");
    }

    static Prompter of(Elicitation elicitation, Duration timeout, String operation) {
        return elicitation == null ? Prompter.NONE : new ElicitationPrompter(elicitation, timeout, operation);
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
     * The protocol hands back only the answers of the last round, so the request state
     * carries the earlier ones, together with the operation they were given for. Answers
     * that come back with any other operation are not taken: the user is asked again.
     */
    private Optional<Boolean> askAcrossRetry(String message) {
        JsonObject known = answers();
        String key = INPUT_KEY_PREFIX + asked++;
        if (!known.containsKey(key) && bound && elicitation.inputResponses().has(key)) {
            known.put(key, answer(elicitation.inputResponses().getElicitationResponse(key)).orElse(null));
        }
        if (known.containsKey(key)) {
            return Optional.ofNullable(known.getBoolean(key));
        }
        throw elicitation.inputRequired()
            .addElicitationRequest(key, request(message))
            .setRequestState(encodeState(known))
            .build();
    }

    private JsonObject answers() {
        if (answers == null) {
            JsonObject state = decodeState(elicitation.requestState());
            bound = state != null && operation.equals(state.getString("op"));
            answers = bound && state.getJsonObject("answers") != null ? state.getJsonObject("answers")
                    : new JsonObject();
        }
        return answers;
    }

    private String encodeState(JsonObject known) {
        String json = new JsonObject().put("op", operation).put("answers", known).encode();
        return Base64.getUrlEncoder().withoutPadding().encodeToString(json.getBytes(StandardCharsets.UTF_8));
    }

    private static JsonObject decodeState(String state) {
        if (state == null) {
            return null;
        }
        try {
            return new JsonObject(new String(Base64.getUrlDecoder().decode(state), StandardCharsets.UTF_8));
        }
        catch (IllegalArgumentException | DecodeException e) {
            return null;
        }
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

    /**
     * What a confirmation is for: a hash over tool, target, caller and every argument,
     * sensitive ones included, in a form that is the same on every instance.
     */
    static String operation(String tool, String system, String realm, Caller caller, Map<String, Object> args) {
        Map<String, Object> operation = new TreeMap<>();
        operation.put("tool", tool);
        operation.put("system", system);
        operation.put("realm", realm);
        operation.put("caller", caller == null ? null : caller.subject());
        operation.put("args", canonical(args));
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                .digest(new JsonObject(operation).encode().getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        }
        catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static Object canonical(Object value) {
        if (value instanceof JsonObject o) {
            return canonical(o.getMap());
        }
        if (value instanceof JsonArray a) {
            return canonical(a.getList());
        }
        if (value instanceof Map<?, ?> m) {
            Map<String, Object> sorted = new TreeMap<>();
            m.forEach((k, v) -> sorted.put(String.valueOf(k), canonical(v)));
            return sorted;
        }
        if (value instanceof List<?> l) {
            return l.stream().map(ElicitationPrompter::canonical).collect(Collectors.toCollection(ArrayList::new));
        }
        return value == null || value instanceof Number || value instanceof Boolean ? value : String.valueOf(value);
    }

}
