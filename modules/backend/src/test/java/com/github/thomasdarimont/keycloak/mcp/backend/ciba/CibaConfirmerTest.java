package com.github.thomasdarimont.keycloak.mcp.backend.ciba;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.github.thomasdarimont.keycloak.mcp.access.Caller;
import com.github.thomasdarimont.keycloak.mcp.backend.Fixtures;
import com.github.thomasdarimont.keycloak.mcp.backend.ciba.CibaSettings.When;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolSpec;
import com.github.thomasdarimont.keycloak.mcp.confirm.ConfirmationRequest;
import com.github.thomasdarimont.keycloak.mcp.confirm.Decision;
import com.github.thomasdarimont.keycloak.mcp.confirm.Prompter;
import com.github.thomasdarimont.keycloak.mcp.spi.ProviderConfig;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import io.vertx.core.json.JsonObject;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The confirmer against a fake realm: discovery, backchannel endpoint, token endpoint.
 */
class CibaConfirmerTest {

    private static final ToolSpec DELETE = Fixtures.specs()
        .stream()
        .filter(s -> s.name().equals("keycloak_user_delete"))
        .findFirst()
        .orElseThrow();

    private HttpServer server;
    private String issuer;
    /** Scripted token endpoint answers: {@code 200} or an OAuth error code. */
    private final Deque<String> tokenAnswers = new ArrayDeque<>();
    private final List<Map<String, String>> backchannelRequests = new CopyOnWriteArrayList<>();
    private final List<String> authHeaders = new CopyOnWriteArrayList<>();

    @BeforeEach
    void start() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        issuer = "http://127.0.0.1:" + server.getAddress().getPort() + "/realms/demo";
        server.createContext("/realms/demo/.well-known/openid-configuration",
                x -> json(x, 200, new JsonObject().put("issuer", issuer)
                    .put("token_endpoint", issuer + "/protocol/openid-connect/token")
                    .put("backchannel_authentication_endpoint", issuer + "/protocol/openid-connect/ext/ciba/auth")));
        server.createContext("/realms/demo/protocol/openid-connect/ext/ciba/auth", x -> {
            authHeaders.add(x.getRequestHeaders().getFirst("Authorization"));
            backchannelRequests.add(form(x));
            json(x, 200, new JsonObject().put("auth_req_id", "req-1").put("expires_in", 10).put("interval", 1));
        });
        server.createContext("/realms/demo/protocol/openid-connect/token", x -> {
            Map<String, String> f = form(x);
            assertEquals(CibaClient.GRANT_TYPE, f.get("grant_type"));
            assertEquals("req-1", f.get("auth_req_id"));
            String answer = tokenAnswers.isEmpty() ? "authorization_pending" : tokenAnswers.poll();
            if (answer.equals("200")) {
                json(x, 200, new JsonObject().put("access_token", "x").put("token_type", "Bearer"));
            }
            else {
                json(x, 400, new JsonObject().put("error", answer).put("error_description", "scripted"));
            }
        });
        server.start();
    }

    @AfterEach
    void stop() {
        server.stop(0);
    }

    private static Map<String, String> form(HttpExchange x) throws IOException {
        String body = new String(x.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
        return java.util.Arrays.stream(body.split("&"))
            .map(kv -> kv.split("=", 2))
            .collect(java.util.stream.Collectors.toMap(kv -> kv[0],
                    kv -> java.net.URLDecoder.decode(kv.length > 1 ? kv[1] : "", StandardCharsets.UTF_8)));
    }

    private static void json(HttpExchange x, int status, JsonObject body) throws IOException {
        byte[] bytes = body.encode().getBytes(StandardCharsets.UTF_8);
        x.getResponseHeaders().add("Content-Type", "application/json");
        x.sendResponseHeaders(status, bytes.length);
        try (OutputStream out = x.getResponseBody()) {
            out.write(bytes);
        }
    }

    private CibaConfirmer confirmer(Map<String, String> extra) {
        Map<String, String> values = new java.util.HashMap<>(Map.of("enabled", "true", "client-id", "mcp-ciba",
                "client-secret", "s3cr3t", "issuer", issuer, "timeout-seconds", "5", "flow", "blocking"));
        values.putAll(extra);
        CibaSettings settings = CibaSettings.from(new ProviderConfig(CibaSettings.ID, values), 120);
        return new CibaConfirmer(settings, "http://unused/realms/x", null).pollFloor(Duration.ofMillis(50));
    }

    private static ConfirmationRequest request(Caller caller, Prompter prompter) {
        return new ConfirmationRequest(DELETE, "prod", "demo", Map.of("id", "u1", "username", "dave"), false, caller,
                prompter);
    }

    private static final Caller ALICE = Caller.of("sub-1", "alice", "demo", Set.of("realm:admin"))
        .withToken("raw", Map.of("iss", "http://unused/realms/demo", "email", "alice@example.com"));

    @Test
    void approvalConfirmsTheOperation() {
        tokenAnswers.addAll(List.of("authorization_pending", "slow_down", "200"));
        Decision d = confirmer(Map.of()).confirm(request(ALICE, Prompter.NONE));
        assertEquals(Decision.Outcome.CONFIRMED, d.outcome(), String.valueOf(d.message()));
        Map<String, String> bc = backchannelRequests.get(0);
        assertEquals("alice", bc.get("login_hint"));
        assertEquals("openid", bc.get("scope"));
        String binding = bc.get("binding_message");
        assertTrue(CibaConfirmer.BINDING_MESSAGE.matcher(binding).matches(), binding);
        assertTrue(binding.startsWith("kc-mcp-"), binding);
        assertEquals("Basic " + java.util.Base64.getEncoder().encodeToString("mcp-ciba:s3cr3t".getBytes()),
                authHeaders.get(0));
    }

    @Test
    void declineCancelsExpiryAndTimeoutLeaveItUnconfirmed() {
        tokenAnswers.add("access_denied");
        Decision declined = confirmer(Map.of()).confirm(request(ALICE, Prompter.NONE));
        assertEquals(Decision.Outcome.DECLINED, declined.outcome());
        assertTrue(declined.message().contains("alice declined"), declined.message());

        tokenAnswers.add("expired_token");
        Decision expired = confirmer(Map.of()).confirm(request(ALICE, Prompter.NONE));
        assertEquals(Decision.Outcome.CONFIRMATION_REQUIRED, expired.outcome());
        assertTrue(expired.message().contains("expired"), expired.message());

        // never answered: the confirmer's own timeout ends the wait
        Decision timeout = confirmer(Map.of("timeout-seconds", "1")).confirm(request(ALICE, Prompter.NONE));
        assertEquals(Decision.Outcome.CONFIRMATION_REQUIRED, timeout.outcome());
        assertTrue(timeout.message().contains("in time"), timeout.message());
    }

    @Test
    void abstainsWhenThereIsNobodyToAskOrWhenTheClientCanAsk() {
        CibaConfirmer c = confirmer(Map.of());
        assertEquals(Decision.Outcome.ABSTAIN, c.confirm(request(Caller.NONE, Prompter.NONE)).outcome());
        Prompter elicitation = new Prompter() {
            @Override
            public boolean available() {
                return true;
            }

            @Override
            public java.util.Optional<Boolean> askYesNo(String message) {
                return java.util.Optional.of(true);
            }
        };
        assertEquals(Decision.Outcome.ABSTAIN,
                confirmer(Map.of("when", "without-elicitation")).confirm(request(ALICE, elicitation)).outcome());
        tokenAnswers.add("200");
        assertEquals(Decision.Outcome.CONFIRMED, c.confirm(request(ALICE, elicitation)).outcome(),
                "when=always asks the device even though the client could ask");
        assertTrue(backchannelRequests.size() == 1, "only the always case reached the realm");

        CibaSettings off = CibaSettings.from(new ProviderConfig(CibaSettings.ID, Map.of()), 120);
        assertEquals(Decision.Outcome.ABSTAIN,
                new CibaConfirmer(off, issuer, null).confirm(request(ALICE, Prompter.NONE)).outcome());
    }

    @Test
    void loginHintAndIssuerCanComeFromTheToken() {
        tokenAnswers.add("200");
        CibaSettings settings = CibaSettings.from(
                new ProviderConfig(CibaSettings.ID, Map.of("enabled", "true", "client-id", "mcp-ciba", "client-secret",
                        "s", "login-hint", "email", "binding-message-prefix", "ACME Corp!", "flow", "blocking")),
                120);
        // issuer=caller: the token says http://unused/realms/demo, which the test maps to
        // the
        // fake realm
        CibaConfirmer c = new CibaConfirmer(settings, "http://fallback/realms/x",
                iss -> new CibaClient(null, issuer, "mcp-ciba", "s", "openid"))
            .pollFloor(Duration.ofMillis(50));
        assertEquals(Decision.Outcome.CONFIRMED, c.confirm(request(ALICE, Prompter.NONE)).outcome());
        Map<String, String> bc = backchannelRequests.get(0);
        assertEquals("alice@example.com", bc.get("login_hint"));
        assertTrue(bc.get("binding_message").startsWith("ACMECorp!-"), bc.get("binding_message"));
    }

    @Test
    void settingsNeedTheClientWhenOn() {
        IllegalStateException e = assertThrows(IllegalStateException.class,
                () -> CibaSettings.from(new ProviderConfig(CibaSettings.ID, Map.of("enabled", "true")), 120));
        assertTrue(e.getMessage().contains("client-id"), e.getMessage());
        CibaSettings s = CibaSettings.from(
                new ProviderConfig(CibaSettings.ID,
                        Map.of("enabled", "true", "client-id", "c", "client-secret", "s", "when", "no-elicitation")),
                90);
        assertEquals(When.WITHOUT_ELICITATION, s.when());
        assertEquals(90, s.timeoutSeconds());
        assertTrue(s.issuerFromCaller());
    }

    @Test
    void bindingMessageIsStableAndBoundToTheOperation() {
        ConfirmationRequest a = request(ALICE, Prompter.NONE);
        ConfirmationRequest b = new ConfirmationRequest(DELETE, "prod", "demo", Map.of("id", "u2", "username", "dave"),
                false, ALICE, Prompter.NONE);
        assertEquals(CibaConfirmer.operationHash(a), CibaConfirmer.operationHash(request(ALICE, Prompter.NONE)));
        assertTrue(!CibaConfirmer.operationHash(a).equals(CibaConfirmer.operationHash(b)));
        assertEquals(10, CibaConfirmer.operationHash(a).length());
        String longPrefix = "x".repeat(60);
        assertTrue(CibaConfirmer.BINDING_MESSAGE.matcher(CibaConfirmer.bindingMessage(longPrefix, a)).matches());
        assertEquals(CibaConfirmer.operationHash(a), CibaConfirmer.bindingMessage("", a));
    }

    @Test
    void providerNeutralOptions() {
        tokenAnswers.add("200");
        Decision d = confirmer(Map.of("client-auth", "client_secret_post", "requested-expiry", "true", "acr-values",
                "mfa", "binding-message", "false"))
            .confirm(request(ALICE, Prompter.NONE));
        assertEquals(Decision.Outcome.CONFIRMED, d.outcome());
        Map<String, String> bc = backchannelRequests.get(0);
        assertEquals("mcp-ciba", bc.get("client_id"), "client_secret_post puts the credentials into the form");
        assertEquals("s3cr3t", bc.get("client_secret"));
        assertEquals(null, authHeaders.get(0), "no Basic header then");
        assertEquals("5", bc.get("requested_expiry"));
        assertEquals("mfa", bc.get("acr_values"));
        assertTrue(!bc.containsKey("binding_message"), bc.toString());

        tokenAnswers.add("invalid_grant");
        Decision expired = confirmer(Map.of()).confirm(request(ALICE, Prompter.NONE));
        assertEquals(Decision.Outcome.CONFIRMATION_REQUIRED, expired.outcome(),
                "invalid_grant, as some providers answer after expiry, ends the wait too");
    }

    @Test
    void twoStepFilesThenCollectsWithNumberMatching() {
        CibaConfirmer c = confirmer(Map.of("flow", "two-step", "poll-wait-seconds", "1"));
        ConfirmationRequest req = new ConfirmationRequest(DELETE, "prod", "demo",
                Map.of("id", "u1", "username", "dave"), false, ALICE, Prompter.NONE, "LM Studio");

        Decision first = c.confirm(req);
        assertEquals(Decision.Outcome.CONFIRMATION_REQUIRED, first.outcome());
        @SuppressWarnings("unchecked")
        Map<String, Object> approval = (Map<String, Object>) first.details().get("approval");
        assertEquals("requested", approval.get("status"));
        String code = String.valueOf(approval.get("code"));
        assertTrue(code.matches("[1-9][0-9]"), code);
        assertTrue(first.message().contains("number " + code), first.message());
        assertTrue(String.valueOf(first.details().get("howTo")).contains("call again"), first.details().toString());
        assertEquals(1, c.pendingCount());
        Map<String, String> bc = backchannelRequests.get(0);
        assertEquals(code, bc.get("code"), "the device gets the number as an additional parameter");
        assertEquals("LM Studio", bc.get("requester"));
        assertEquals(DELETE.title() + " (realm demo)", bc.get("operation"));
        assertEquals(approval.get("bindingMessage"), bc.get("binding_message"));

        // nobody answered yet: the collecting call waits a moment and reports pending
        Decision waiting = c.confirm(req);
        assertEquals(Decision.Outcome.CONFIRMATION_REQUIRED, waiting.outcome());
        @SuppressWarnings("unchecked")
        Map<String, Object> pendingApproval = (Map<String, Object>) waiting.details().get("approval");
        assertEquals("pending", pendingApproval.get("status"));
        assertEquals(code, pendingApproval.get("code"), "same request, same number");
        assertEquals(1, backchannelRequests.size(), "no second request was filed");

        tokenAnswers.add("200");
        assertEquals(Decision.Outcome.CONFIRMED, c.confirm(req).outcome());
        assertEquals(0, c.pendingCount());

        // a decline ends the pending request too
        c.confirm(req);
        tokenAnswers.add("access_denied");
        Decision declined = c.confirm(req);
        assertEquals(Decision.Outcome.DECLINED, declined.outcome());
        assertEquals(0, c.pendingCount());

        // and so does an expiry: the next call starts over with a new request
        c.confirm(req);
        tokenAnswers.add("expired_token");
        Decision expired = c.confirm(req);
        assertEquals("expired", ((Map<?, ?>) expired.details().get("approval")).get("status"));
        assertEquals(0, c.pendingCount());
        assertEquals(Decision.Outcome.CONFIRMATION_REQUIRED, c.confirm(req).outcome());
        assertEquals(4, backchannelRequests.size());
    }

    @Test
    void twoStepWithoutNumberMatchingOrExtras() {
        CibaConfirmer c = confirmer(
                Map.of("flow", "two-step", "number-matching", "false", "extra-parameters", "false"));
        Decision first = c.confirm(request(ALICE, Prompter.NONE));
        Map<?, ?> approval = (Map<?, ?>) first.details().get("approval");
        assertTrue(!approval.containsKey("code"), approval.toString());
        Map<String, String> bc = backchannelRequests.get(0);
        assertTrue(!bc.containsKey("code") && !bc.containsKey("requester") && !bc.containsKey("operation"),
                bc.toString());
    }
}
