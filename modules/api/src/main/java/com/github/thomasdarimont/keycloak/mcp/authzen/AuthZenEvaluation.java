package com.github.thomasdarimont.keycloak.mcp.authzen;

import java.time.Instant;
import java.util.Objects;

import com.github.thomasdarimont.keycloak.mcp.access.AccessCheck;

import io.vertx.core.json.JsonObject;

/**
 * One AuthZEN evaluation request (OpenID AuthZEN Authorization API 1.0,
 * {@code POST /access/v1/evaluation}): subject, action, resource, context. Immutable: the
 * accessors hand out copies, the {@code with} methods give changed copies, so a
 * {@link AuthZenRequestCustomizer} cannot change what another one sees behind its back.
 *
 * @param subject who acts: the caller from the token
 * @param action what: the tool, its level and its Admin REST operation
 * @param resource on what: read from the operation's path bindings
 * @param context everything else: system, realm, acting client, time, arguments
 */
public record AuthZenEvaluation(JsonObject subject, JsonObject action, JsonObject resource, JsonObject context) {

    public AuthZenEvaluation {
        subject = copy(subject, "subject");
        action = copy(action, "action");
        resource = copy(resource, "resource");
        context = context == null ? new JsonObject() : context.copy();
    }

    private static JsonObject copy(JsonObject o, String name) {
        return Objects.requireNonNull(o, name).copy();
    }

    /**
     * The evaluation of a tool call, as the built-in engine sends it
     * ({@link AuthZenMapping}).
     *
     * @param sendArgs whether the call's arguments go into the context (sensitive ones
     * masked either way)
     */
    public static AuthZenEvaluation of(AccessCheck.Context call, boolean sendArgs, Instant now) {
        JsonObject r = AuthZenMapping.request(call, sendArgs, now);
        return new AuthZenEvaluation(r.getJsonObject("subject"), r.getJsonObject("action"), r.getJsonObject("resource"),
                r.getJsonObject("context"));
    }

    @Override
    public JsonObject subject() {
        return subject.copy();
    }

    @Override
    public JsonObject action() {
        return action.copy();
    }

    @Override
    public JsonObject resource() {
        return resource.copy();
    }

    @Override
    public JsonObject context() {
        return context.copy();
    }

    public AuthZenEvaluation withSubject(JsonObject newSubject) {
        return new AuthZenEvaluation(newSubject, action, resource, context);
    }

    public AuthZenEvaluation withAction(JsonObject newAction) {
        return new AuthZenEvaluation(subject, newAction, resource, context);
    }

    public AuthZenEvaluation withResource(JsonObject newResource) {
        return new AuthZenEvaluation(subject, action, newResource, context);
    }

    public AuthZenEvaluation withContext(JsonObject newContext) {
        return new AuthZenEvaluation(subject, action, resource, newContext);
    }

    /** A copy with one more context entry, e.g. a ticket id or a tenant attribute. */
    public AuthZenEvaluation withContextValue(String key, Object value) {
        return withContext(context.copy().put(key, value));
    }

    /** The request body. */
    public JsonObject toJson() {
        return new JsonObject().put("subject", subject.copy())
            .put("action", action.copy())
            .put("resource", resource.copy())
            .put("context", context.copy());
    }
}
