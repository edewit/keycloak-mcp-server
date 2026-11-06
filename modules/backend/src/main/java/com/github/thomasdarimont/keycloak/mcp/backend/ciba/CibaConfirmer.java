package com.github.thomasdarimont.keycloak.mcp.backend.ciba;

import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;
import java.util.regex.Pattern;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;

import org.jboss.logging.Logger;

import com.github.thomasdarimont.keycloak.mcp.access.Caller;
import com.github.thomasdarimont.keycloak.mcp.backend.ciba.CibaClient.Poll;
import com.github.thomasdarimont.keycloak.mcp.backend.ciba.CibaClient.Started;
import com.github.thomasdarimont.keycloak.mcp.backend.ciba.CibaSettings.Flow;
import com.github.thomasdarimont.keycloak.mcp.config.McpServerConfig;
import com.github.thomasdarimont.keycloak.mcp.confirm.ConfirmationRequest;
import com.github.thomasdarimont.keycloak.mcp.confirm.Confirmer;
import com.github.thomasdarimont.keycloak.mcp.confirm.Decision;

import io.quarkus.runtime.StartupEvent;
import io.vertx.core.json.JsonObject;

/**
 * Confirms destructive tools through OpenID Connect CIBA: the caller, identified by the
 * MCP session's token, gets an authentication request on their own device (whatever the
 * provider's authentication channel delivers it to) carrying a binding message that names
 * the operation; the tool runs once they approve, is cancelled when they decline, and
 * stays unconfirmed when nobody answers in time. Unlike {@code confirm: true}, which the
 * model writes, and elicitation, which the MCP client answers, the approval comes from a
 * second channel the model never touches.
 * <p>
 * Two-step flow (default): the first call files the request and answers
 * {@code confirmation_required} at once, with the binding message and, for number
 * matching, a two-digit {@code code} the device asks the user for; the next call with the
 * same arguments collects the decision. Blocking flow: the call waits for the device.
 * Works with any CIBA-capable provider (tested against Keycloak). Configuration
 * {@code kc-mcp.spi.ciba-confirmer.*} ({@link CibaSettings}); off by default, abstains
 * for anonymous callers.
 */
@ApplicationScoped
public class CibaConfirmer implements Confirmer {

    private static final Logger LOG = Logger.getLogger(CibaConfirmer.class);

    /** Keycloak's rule for the binding message, stricter than most providers'. */
    static final Pattern BINDING_MESSAGE = Pattern.compile("^[a-zA-Z0-9-._+/!?#]{1,50}$");

    /** Additional request parameters the device may show or ask for. */
    static final String PARAM_CODE = "code";
    static final String PARAM_REQUESTER = "requester";
    static final String PARAM_OPERATION = "operation";

    /** A filed request waiting for the device (two-step flow). */
    record Pending(String authReqId, String requestId, String code, String binding, String hint, String operation,
            long deadlineNanos, Duration interval) {
        boolean expired() {
            return System.nanoTime() >= deadlineNanos;
        }

        long secondsLeft() {
            return Math.max(0, Duration.ofNanos(deadlineNanos - System.nanoTime()).toSeconds());
        }
    }

    private final CibaSettings settings;
    private final String defaultIssuer;
    private final Function<String, CibaClient> clients;
    private final Map<String, CibaClient> byIssuer = new ConcurrentHashMap<>();
    private final Map<String, Pending> pending = new ConcurrentHashMap<>();
    private final SecureRandom random = new SecureRandom();
    private Duration pollFloor = Duration.ofSeconds(1);

    @Inject
    public CibaConfirmer(McpServerConfig config) {
        this(CibaSettings.from(config), config.url() + "/realms/" + config.authRealm(), null);
    }

    /**
     * @param clients makes the client of an issuer; {@code null} for the real HTTP one
     */
    public CibaConfirmer(CibaSettings settings, String defaultIssuer, Function<String, CibaClient> clients) {
        this.settings = settings;
        this.defaultIssuer = defaultIssuer;
        HttpClient http = clients == null ? CibaClient.newHttpClient() : null;
        this.clients = clients != null ? clients : issuer -> new CibaClient(http, issuer, settings.clientId(),
                settings.clientSecret(), settings.clientAuth(), settings.scope(), settings.acrValues());
    }

    void onStart(@Observes StartupEvent event) {
        if (settings.enabled()) {
            LOG.infof(
                    "CIBA confirmer on: destructive tools need the caller's approval on their device (client '%s'"
                            + " at %s, %s, %s flow%s, login hint %s, %d s)",
                    settings.clientId(), settings.issuerFromCaller() ? "the caller's issuer" : settings.issuer(),
                    settings.when() == CibaSettings.When.ALWAYS ? "always" : "when the client has no elicitation",
                    settings.flow() == Flow.TWO_STEP ? "two-step" : "blocking",
                    settings.flow() == Flow.TWO_STEP && settings.numberMatching() ? " with number matching" : "",
                    settings.loginHint(), settings.timeoutSeconds());
        }
    }

    @Override
    public String id() {
        return CibaSettings.ID;
    }

    @Override
    public String displayName() {
        return "CIBA confirmation";
    }

    @Override
    public String description() {
        return "Asks the caller to approve destructive operations on their own device through OpenID Connect CIBA.";
    }

    @Override
    public int order() {
        return 1000;
    }

    public CibaSettings settings() {
        return settings;
    }

    @Override
    public boolean asksTheHuman() {
        return settings.enabled();
    }

    /** Shortest pause between polls (tests lower it). */
    CibaConfirmer pollFloor(Duration floor) {
        this.pollFloor = floor;
        return this;
    }

    /** Requests filed and not yet decided (two-step flow). */
    public int pendingCount() {
        pending.values().removeIf(Pending::expired);
        return pending.size();
    }

    @Override
    public Decision confirm(ConfirmationRequest r) {
        if (!settings.enabled()) {
            return Decision.abstain();
        }
        if (settings.when() == CibaSettings.When.WITHOUT_ELICITATION && r.prompter().available()) {
            return Decision.abstain();
        }
        Caller caller = r.caller();
        if (caller.isAnonymous()) {
            LOG.debugf("CIBA confirmer: anonymous caller, nobody to ask for %s", r.tool().name());
            return Decision.abstain();
        }
        String hint = loginHint(caller);
        if (hint == null) {
            LOG.warnf("CIBA confirmer: caller %s has no %s to address the request to, abstaining", caller,
                    settings.loginHint());
            return Decision.abstain();
        }
        String issuer = settings.issuerFromCaller() ? issuerOf(caller) : settings.issuer();
        CibaClient client = byIssuer.computeIfAbsent(issuer, clients);
        String operation = r.tool().title() + (r.realm() != null ? " (realm " + r.realm() + ")" : "");
        if (settings.flow() == Flow.BLOCKING) {
            Pending p = file(client, r, hint, operation, null);
            return await(client, p, p.deadlineNanos);
        }
        String key = (caller.subject() != null ? caller.subject() : hint) + "|" + issuer + "|" + operationHash(r);
        Pending p = pending.get(key);
        if (p != null && p.expired()) {
            pending.remove(key, p);
            p = null;
        }
        if (p == null) {
            String code = settings.numberMatching() ? String.valueOf(10 + random.nextInt(90)) : null;
            p = file(client, r, hint, operation, code);
            pending.put(key, p);
            return awaiting(p, true);
        }
        long waitUntil = Math.min(p.deadlineNanos,
                System.nanoTime() + Duration.ofSeconds(settings.pollWaitSeconds()).toNanos());
        Decision d = await(client, p, waitUntil);
        if (d.outcome() == Decision.Outcome.CONFIRMATION_REQUIRED && !p.expired()
                && Boolean.TRUE.equals(d.details().get("waiting"))) {
            return awaiting(p, false);
        }
        pending.remove(key, p);
        return d;
    }

    /** Files the request with the provider. */
    private Pending file(CibaClient client, ConfirmationRequest r, String hint, String operation, String code) {
        String binding = settings.bindingMessage() ? bindingMessage(settings.bindingMessagePrefix(), r) : null;
        Map<String, String> extra = new LinkedHashMap<>();
        if (code != null) {
            extra.put(PARAM_CODE, code);
        }
        if (settings.extraParameters()) {
            if (r.clientName() != null) {
                extra.put(PARAM_REQUESTER, cut(r.clientName(), 200));
            }
            extra.put(PARAM_OPERATION, cut(operation, 200));
        }
        Started started = client.start(hint, binding, settings.requestedExpiry() ? settings.timeoutSeconds() : 0,
                extra);
        int budget = Math.min(settings.timeoutSeconds(), started.expiresIn());
        String requestId = fingerprint(started.authReqId());
        LOG.infof("CIBA request %s for %s: %s %s (binding message %s%s, up to %d s)", requestId, hint, r.tool().name(),
                r.realm() == null ? "" : "realm " + r.realm(), binding == null ? "none" : binding,
                code == null ? "" : ", code " + code, budget);
        Duration interval = Duration.ofSeconds(Math.max(1, started.interval()));
        if (interval.compareTo(pollFloor) < 0) {
            interval = pollFloor;
        }
        return new Pending(started.authReqId(), requestId, code, binding, hint, operation,
                System.nanoTime() + Duration.ofSeconds(budget).toNanos(), interval);
    }

    /**
     * Polls until the device answered or {@code untilNanos} passed; "still waiting" comes
     * back as CONFIRMATION_REQUIRED with {@code waiting=true} in the details.
     */
    private Decision await(CibaClient client, Pending p, long untilNanos) {
        Duration interval = p.interval();
        while (true) {
            if (p.expired()) {
                return Decision.confirmationRequired("No approval for '" + p.operation() + "' arrived in time: "
                        + p.hint() + " was asked on their device" + bindingNote(p.binding())
                        + ". Nothing was changed; call again to send a new request when they are ready to approve.",
                        Map.of("approval", Map.of("status", "expired"), "howTo",
                                "Call again with the same arguments to send a new request to the user's device."));
            }
            if (System.nanoTime() >= untilNanos) {
                return Decision.confirmationRequired("still waiting", Map.of("waiting", true));
            }
            try {
                Thread.sleep(interval);
            }
            catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return Decision.declined("Confirmation of '" + p.operation() + "' interrupted.");
            }
            Poll poll = client.poll(p.authReqId());
            switch (poll.status()) {
                case APPROVED -> {
                    LOG.infof("CIBA request %s approved by %s", p.requestId(), p.hint());
                    return Decision.confirmed();
                }
                case DENIED -> {
                    LOG.infof("CIBA request %s declined by %s", p.requestId(), p.hint());
                    return Decision.declined(p.hint() + " declined '" + p.operation() + "' on their device"
                            + bindingNote(p.binding()) + ".", Map.of("approval", Map.of("status", "declined")));
                }
                case EXPIRED -> {
                    return Decision.confirmationRequired("The approval request for '" + p.operation()
                            + "' expired before " + p.hint() + " answered" + bindingNote(p.binding())
                            + ". Nothing was changed; call again to send a new request when they are ready to approve.",
                            Map.of("approval", Map.of("status", "expired"), "howTo",
                                    "Call again with the same arguments to send a new request to the user's device."));
                }
                case SLOW_DOWN -> interval = interval.plusSeconds(5);
                case PENDING -> {
                    // keep polling
                }
            }
        }
    }

    /** The two-step answer while the device has not decided. */
    private Decision awaiting(Pending p, boolean fresh) {
        Map<String, Object> approval = new LinkedHashMap<>();
        approval.put("status", fresh ? "requested" : "pending");
        approval.put("user", p.hint());
        if (p.binding() != null) {
            approval.put("bindingMessage", p.binding());
        }
        if (p.code() != null) {
            approval.put("code", p.code());
        }
        approval.put("expiresInSeconds", p.secondsLeft());
        String code = p.code() == null ? "" : " The device asks for the number " + p.code() + ".";
        String message = fresh
                ? "'" + p.operation() + "' needs " + p.hint() + "'s approval on their device: a request"
                        + bindingNote(p.binding()) + " was sent." + code
                : "Still waiting for " + p.hint() + "'s approval of '" + p.operation() + "' on their device"
                        + bindingNote(p.binding()) + "." + code + " " + p.secondsLeft() + " s left.";
        String howTo = "Tell the user to approve the request on their device"
                + (p.code() == null ? "" : " and to enter the number " + p.code() + " when asked")
                + ", then call again with the same arguments to continue. Nothing has been changed yet.";
        return Decision.confirmationRequired(message, Map.of("approval", approval, "howTo", howTo));
    }

    /** Keycloak's {@code auth_req_id} is a long JWE; the log shows its tail. */
    static String fingerprint(String authReqId) {
        return authReqId == null ? "?"
                : authReqId.length() <= 12 ? authReqId : "…" + authReqId.substring(authReqId.length() - 12);
    }

    private static String bindingNote(String binding) {
        return binding == null ? "" : " (binding message " + binding + ")";
    }

    private static String cut(String s, int max) {
        return s.length() <= max ? s : s.substring(0, max);
    }

    private String loginHint(Caller caller) {
        if ("username".equalsIgnoreCase(settings.loginHint()) || "name".equalsIgnoreCase(settings.loginHint())) {
            return caller.name();
        }
        Object claim = caller.claim(settings.loginHint());
        return claim == null ? null : String.valueOf(claim);
    }

    private String issuerOf(Caller caller) {
        Object iss = caller.claim("iss");
        return iss instanceof String s && !s.isBlank() ? s : defaultIssuer;
    }

    /**
     * {@code <prefix>-<hash>}: the hash covers tool, system, realm and arguments, so the
     * message on the device belongs to exactly this operation.
     */
    static String bindingMessage(String prefix, ConfirmationRequest r) {
        String clean = prefix == null ? "" : prefix.replaceAll("[^a-zA-Z0-9-._+/!?#]", "");
        if (clean.length() > 38) {
            clean = clean.substring(0, 38);
        }
        String message = (clean.isEmpty() ? "" : clean + "-") + operationHash(r);
        if (!BINDING_MESSAGE.matcher(message).matches()) {
            message = operationHash(r);
        }
        return message;
    }

    static String operationHash(ConfirmationRequest r) {
        JsonObject canonical = new JsonObject().put("tool", r.tool().name())
            .put("system", r.system())
            .put("realm", r.realm())
            .put("args", new JsonObject(new TreeMap<>(r.args())));
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                .digest(canonical.encode().getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest, 0, 5);
        }
        catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
