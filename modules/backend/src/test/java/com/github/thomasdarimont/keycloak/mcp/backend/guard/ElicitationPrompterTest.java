package com.github.thomasdarimont.keycloak.mcp.backend.guard;

import java.lang.reflect.Proxy;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.junit.jupiter.api.Test;

import com.github.thomasdarimont.keycloak.mcp.access.Caller;
import com.github.thomasdarimont.keycloak.mcp.confirm.Prompter;

import io.quarkiverse.mcp.server.Elicitation;
import io.quarkiverse.mcp.server.ElicitationRequest;
import io.quarkiverse.mcp.server.ElicitationResponse;
import io.quarkiverse.mcp.server.InputRequiredException;
import io.quarkiverse.mcp.server.InputResponses;
import io.quarkiverse.mcp.server.Meta;
import io.quarkiverse.mcp.server.Root;
import io.quarkiverse.mcp.server.SamplingResponse;
import io.quarkiverse.mcp.server.UrlElicitationRequest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ElicitationPrompterTest {

    private static final Caller ALICE = Caller.of("alice-id", "alice", "demo", java.util.Set.of());

    @Test
    void operationIsIndependentOfTheOrderOfTheArguments() {
        Map<String, Object> nestedA = new LinkedHashMap<>();
        nestedA.put("x", 1);
        nestedA.put("y", List.of("a"));
        Map<String, Object> a = new LinkedHashMap<>();
        a.put("id", "u");
        a.put("attributes", nestedA);
        Map<String, Object> nestedB = new LinkedHashMap<>();
        nestedB.put("y", List.of("a"));
        nestedB.put("x", 1);
        Map<String, Object> b = new LinkedHashMap<>();
        b.put("attributes", nestedB);
        b.put("id", "u");
        assertEquals(ElicitationPrompter.operation("t", "s", "r", ALICE, a),
                ElicitationPrompter.operation("t", "s", "r", ALICE, b));
    }

    @Test
    void operationCoversSensitiveArgumentsTargetAndCaller() {
        String base = ElicitationPrompter.operation("t", "s", "r", ALICE, Map.of("password", "one"));
        assertNotEquals(base, ElicitationPrompter.operation("t", "s", "r", ALICE, Map.of("password", "two")));
        assertNotEquals(base, ElicitationPrompter.operation("t", "s", "other", ALICE, Map.of("password", "one")));
        assertNotEquals(base, ElicitationPrompter.operation("t", "other", "r", ALICE, Map.of("password", "one")));
        assertNotEquals(base, ElicitationPrompter.operation("t", "s", "r",
                Caller.of("bob-id", "bob", "demo", java.util.Set.of()), Map.of("password", "one")));
    }

    @Test
    void severalQuestionsAreAskedOnceEachAndAnswersSurviveTheRetries() {
        List<String> asked = new ArrayList<>();
        Map<String, ElicitationResponse> responses = Map.of();
        String state = null;
        for (int round = 0; round < 5; round++) {
            Prompter prompter = prompter("op", responses, state);
            try {
                assertEquals(Optional.of(true), prompter.askYesNo("first"));
                assertEquals(Optional.of(false), prompter.askYesNo("second"));
                assertEquals(List.of("confirm-0", "confirm-1"), asked);
                return;
            }
            catch (InputRequiredException e) {
                String key = e.inputRequests().keySet().iterator().next();
                asked.add(key);
                responses = Map.of(key, accepted(key.equals("confirm-0")));
                state = e.requestState();
            }
        }
        throw new AssertionError("still asking after 5 rounds: " + asked);
    }

    @Test
    void anAnswerForAnotherOperationAsksAgain() {
        InputRequiredException first = assertThrows(InputRequiredException.class,
                () -> prompter("op", Map.of(), null).askYesNo("q"));
        Map<String, ElicitationResponse> yes = Map.of("confirm-0", accepted(true));
        assertEquals(Optional.of(true), prompter("op", yes, first.requestState()).askYesNo("q"));
        assertThrows(InputRequiredException.class, () -> prompter("other", yes, first.requestState()).askYesNo("q"));
        assertThrows(InputRequiredException.class, () -> prompter("op", yes, "%%not-a-state").askYesNo("q"));
        assertThrows(InputRequiredException.class, () -> prompter("op", yes, null).askYesNo("q"));
    }

    private static Prompter prompter(String operation, Map<String, ElicitationResponse> responses, String state) {
        return new ElicitationPrompter(new StatelessElicitation(responses, state), Duration.ofSeconds(1), operation);
    }

    private static ElicitationResponse accepted(boolean confirm) {
        ElicitationResponse.Content content = proxy(ElicitationResponse.Content.class,
                (p, m, a) -> "getBoolean".equals(m.getName()) ? (Object) confirm : null);
        return new ElicitationResponse(ElicitationResponse.Action.ACCEPT, content,
                proxy(Meta.class, (p, m, a) -> null));
    }

    @SuppressWarnings("unchecked")
    private static <T> T proxy(Class<T> type, java.lang.reflect.InvocationHandler handler) {
        return (T) Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[] { type }, handler);
    }

    private record StatelessElicitation(Map<String, ElicitationResponse> responses,
            String state) implements Elicitation {

        @Override
        public boolean isSupported() {
            return true;
        }

        @Override
        public boolean isFormModeSupported() {
            return true;
        }

        @Override
        public boolean isUrlModeSupported() {
            return false;
        }

        @Override
        public ElicitationRequest.Builder requestBuilder() {
            ElicitationRequest request = proxy(ElicitationRequest.class, (p, m, a) -> null);
            return proxy(ElicitationRequest.Builder.class, (p, m, a) -> "build".equals(m.getName()) ? request : p);
        }

        @Override
        public UrlElicitationRequest.Builder urlRequestBuilder() {
            throw new UnsupportedOperationException();
        }

        @Override
        public boolean isServerInitiatedRequestSupported() {
            return false;
        }

        @Override
        public InputResponses inputResponses() {
            return new InputResponses() {
                @Override
                public boolean isEmpty() {
                    return responses.isEmpty();
                }

                @Override
                public boolean has(String key) {
                    return responses.containsKey(key);
                }

                @Override
                public ElicitationResponse getElicitationResponse(String key) {
                    return responses.get(key);
                }

                @Override
                public SamplingResponse getSamplingResponse(String key) {
                    return null;
                }

                @Override
                public List<Root> getRootsResponse(String key) {
                    return null;
                }
            };
        }

        @Override
        public String requestState() {
            return state;
        }
    }

}
