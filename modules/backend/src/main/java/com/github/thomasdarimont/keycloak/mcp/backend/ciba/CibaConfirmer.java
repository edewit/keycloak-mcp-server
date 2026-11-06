package com.github.thomasdarimont.keycloak.mcp.backend.ciba;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;
import java.util.regex.Pattern;
import jakarta.annotation.PreDestroy;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;
import jakarta.ws.rs.client.Client;

import org.jboss.logging.Logger;

import com.github.thomasdarimont.keycloak.mcp.access.Caller;
import com.github.thomasdarimont.keycloak.mcp.backend.ciba.CibaClient.CibaException;
import com.github.thomasdarimont.keycloak.mcp.backend.ciba.CibaClient.Poll;
import com.github.thomasdarimont.keycloak.mcp.backend.ciba.CibaClient.Started;
import com.github.thomasdarimont.keycloak.mcp.backend.ciba.CibaSettings.Flow;
import com.github.thomasdarimont.keycloak.mcp.backend.http.OutboundClients;
import com.github.thomasdarimont.keycloak.mcp.backend.metrics.KcMcpMetrics;
import com.github.thomasdarimont.keycloak.mcp.config.McpServerConfig;
import com.github.thomasdarimont.keycloak.mcp.confirm.ConfirmationRequest;
import com.github.thomasdarimont.keycloak.mcp.confirm.Confirmer;
import com.github.thomasdarimont.keycloak.mcp.confirm.Decision;
import com.github.thomasdarimont.keycloak.mcp.confirm.PendingApproval;
import com.github.thomasdarimont.keycloak.mcp.confirm.PendingApprovalStore;
import com.github.thomasdarimont.keycloak.mcp.spi.Extension;
import com.github.thomasdarimont.keycloak.mcp.spi.ExtensionRegistry;
import com.github.thomasdarimont.keycloak.mcp.spi.ProviderConfig;

import io.quarkus.runtime.StartupEvent;
import io.quarkus.tls.TlsConfigurationRegistry;
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
 * Two-step flow (default): the first call reserves the approval (one per MCP session,
 * caller and operation, atomically in the {@link PendingApprovalStore}), files the
 * request and answers {@code confirmation_required} at once, with the binding message
 * and, for number matching, a two-digit {@code code} the device asks the user for; the
 * next call with the same arguments collects the decision, verifies the ID token of the
 * approval against the provider's keys and the identity it names against the caller, and
 * consumes the approval once. Blocking flow: the call waits for the device. Works with
 * any CIBA-capable provider (tested against Keycloak). Configuration
 * {@code kc-mcp.spi.ciba-confirmer.*} ({@link CibaSettings}); off by default, needs
 * authenticated callers, never leaves a decision to the model.
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

    /** How long a bare reservation lasts: the time to file the request. */
    static final Duration RESERVATION = Duration.ofSeconds(30);

    private final CibaSettings settings;
    private final String defaultIssuer;
    private final Function<String, CibaClient> clients;
    private final Function<CibaClient, CibaIdentityVerifier> verifiers;
    private final PendingApprovalStore store;
    private final boolean callersRequired;
    private final Map<String, CibaClient> byIssuer = new ConcurrentHashMap<>();
    private final SecureRandom random = new SecureRandom();
    private Duration pollFloor = Duration.ofSeconds(1);
    private KcMcpMetrics metrics = KcMcpMetrics.noop();
    /**
     * The JAX-RS client shared by the providers' CIBA clients; {@code null} when the
     * clients come from outside.
     */
    private final Client http;

    @Inject
    public CibaConfirmer(McpServerConfig config, ExtensionRegistry registry, KcMcpMetrics metrics,
            Instance<TlsConfigurationRegistry> tls) {
        this(CibaSettings.from(config), config.url() + "/realms/" + config.authRealm(), null, null,
                registry.extensions(PendingApprovalStore.class)
                    .stream()
                    .min(Comparator.comparingInt(Extension::order))
                    .orElseGet(InMemoryPendingApprovalStore::new),
                config.callerRequired() || config.delegation().delegating(), tls.isResolvable() ? tls.get() : null,
                OutboundClients.Timeouts.of(config));
        this.metrics = metrics;
    }

    public CibaConfirmer(CibaSettings settings, String defaultIssuer, Function<String, CibaClient> clients,
            Function<CibaClient, CibaIdentityVerifier> verifiers, PendingApprovalStore store, boolean callersRequired) {
        this(settings, defaultIssuer, clients, verifiers, store, callersRequired, null,
                OutboundClients.Timeouts.DEFAULT);
    }

    /**
     * @param clients makes the client of an issuer; {@code null} for the real HTTP one
     * @param verifiers makes the verifier of a client; {@code null} for the real one (the
     * client's issuer, its JWKS, the CIBA client as audience)
     * @param tls the registry {@link CibaSettings#tlsConfigurationName()} is looked up
     * in; {@code null} when none is named
     * @param timeouts the global {@code kc-mcp.http.*} timeouts; the confirmer's own
     * settings override them
     */
    public CibaConfirmer(CibaSettings settings, String defaultIssuer, Function<String, CibaClient> clients,
            Function<CibaClient, CibaIdentityVerifier> verifiers, PendingApprovalStore store, boolean callersRequired,
            TlsConfigurationRegistry tls, OutboundClients.Timeouts timeouts) {
        this.settings = settings;
        this.defaultIssuer = defaultIssuer;
        Client http = clients == null && settings.enabled() ? OutboundClients.create(
                timeouts.with(java.util.Optional.ofNullable(settings.connectTimeout()),
                        java.util.Optional.ofNullable(settings.readTimeout())),
                settings.tlsConfigurationName(), tls, "kc-mcp.spi.ciba-confirmer.tls-configuration-name") : null;
        this.http = http;
        this.clients = clients != null ? clients : issuer -> new CibaClient(http, issuer, settings.clientId(),
                settings.clientSecret(), settings.clientAuth(), settings.scope(), settings.acrValues());
        this.verifiers = verifiers != null ? verifiers : client -> new CibaIdentityVerifier(client.jwksUri(),
                settings.tokenIssuer() != null ? settings.tokenIssuer() : client.issuer(), settings.clientId());
        this.store = store == null ? new InMemoryPendingApprovalStore() : store;
        this.callersRequired = callersRequired;
    }

    @PreDestroy
    void close() {
        if (http != null) {
            http.close();
        }
    }

    void onStart(@Observes StartupEvent event) {
        if (!settings.enabled()) {
            return;
        }
        if (!callersRequired) {
            throw new IllegalStateException("kc-mcp.spi.ciba-confirmer.enabled=true needs authenticated callers, or"
                    + " there is nobody whose device could be asked: set kc-mcp.require-caller=true (with"
                    + " quarkus.oidc.tenant-enabled=true), kc-mcp.delegation=forward|exchange, or"
                    + " kc-mcp.profile=shared");
        }
        metrics.pendingApprovals(() -> store.countLive(System.currentTimeMillis()));
        LOG.infof(
                "CIBA confirmer on: destructive tools need the caller's approval on their device (client '%s'"
                        + " at %s, %s, %s flow%s, login hint %s, %d s, approvals in %s)",
                settings.clientId(), settings.issuerFromCaller() ? "the caller's issuer" : settings.issuer(),
                settings.when() == CibaSettings.When.ALWAYS ? "always" : "when the client has no elicitation",
                settings.flow() == Flow.TWO_STEP ? "two-step" : "blocking",
                settings.flow() == Flow.TWO_STEP && settings.numberMatching() ? " with number matching" : "",
                settings.loginHint(), settings.timeoutSeconds(), store.id());
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

    /**
     * Off unless {@code kc-mcp.spi.ciba-confirmer.enabled=true}: then not in the
     * confirmer chain at all.
     */
    @Override
    public boolean isSupported(McpServerConfig serverConfig, ProviderConfig config) {
        return config.getBoolean("enabled", false);
    }

    @Override
    public boolean asksTheHuman() {
        return settings.enabled();
    }

    public CibaSettings settings() {
        return settings;
    }

    public PendingApprovalStore store() {
        return store;
    }

    /** Where the CIBA counters go (tests). */
    CibaConfirmer metrics(KcMcpMetrics metrics) {
        this.metrics = metrics == null ? KcMcpMetrics.noop() : metrics;
        return this;
    }

    /** Shortest pause between polls (tests lower it). */
    CibaConfirmer pollFloor(Duration floor) {
        this.pollFloor = floor;
        return this;
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
            return Decision.confirmationRequired(
                    "This server confirms destructive operations on the caller's own"
                            + " device, and this session has no signed-in caller whose device could be asked. Connect"
                            + " through an authenticated (OAuth) MCP session; nothing was changed.",
                    Map.of("howTo", "Sign in to the MCP server first; confirm: true is not accepted."));
        }
        String hint = loginHint(caller);
        if (hint == null) {
            return Decision.confirmationRequired(
                    "This server confirms destructive operations on the caller's own"
                            + " device, but the caller's token carries no " + settings.loginHint()
                            + " to address the request to; nothing was changed.",
                    Map.of("howTo", "An administrator must fix the login hint of the CIBA confirmer; confirm: true"
                            + " is not accepted."));
        }
        String issuer = settings.issuerFromCaller() ? issuerOf(caller) : settings.issuer();
        CibaClient client = byIssuer.computeIfAbsent(issuer, clients);
        String operation = r.tool().title() + (r.realm() != null ? " (realm " + r.realm() + ")" : "");
        String session = r.connectionId() == null ? "-" : r.connectionId();
        String key = session + "|" + (caller.subject() != null ? caller.subject() : hint) + "|" + issuer + "|"
                + operationHash(r);
        if (settings.flow() == Flow.BLOCKING) {
            PendingApproval p = file(client, r, caller, issuer, hint, operation, null, key);
            return await(client, p, p.expiresAt());
        }
        if (store.reserve(key, System.currentTimeMillis() + RESERVATION.toMillis())) {
            String code = settings.numberMatching() ? String.valueOf(10 + random.nextInt(90)) : null;
            PendingApproval p;
            try {
                p = file(client, r, caller, issuer, hint, operation, code, key);
            }
            catch (RuntimeException e) {
                store.remove(key);
                throw e;
            }
            store.put(p);
            return awaiting(p, true);
        }
        Optional<PendingApproval> found = store.find(key);
        if (found.isEmpty()) {
            // the reservation lapsed between the check and the lookup: start over
            return confirm(r);
        }
        PendingApproval p = found.get();
        if (!p.filed()) {
            return Decision.confirmationRequired(
                    "The approval request for '" + operation + "' is being filed with " + hint
                            + "'s device by a parallel call; call again in a moment.",
                    Map.of("approval", Map.of("status", "filing"), "howTo",
                            "Call again with the same arguments in a few seconds."));
        }
        long waitUntil = Math.min(p.expiresAt(),
                System.currentTimeMillis() + Duration.ofSeconds(settings.pollWaitSeconds()).toMillis());
        Decision d = await(client, p, waitUntil);
        if (d.outcome() == Decision.Outcome.CONFIRMATION_REQUIRED && !p.expired()
                && Boolean.TRUE.equals(d.details().get("waiting"))) {
            return awaiting(p, false);
        }
        if (!store.remove(key) && d.outcome() == Decision.Outcome.CONFIRMED) {
            LOG.warnf("CIBA request %s was consumed by a parallel call; not confirming twice", p.requestId());
            return Decision.confirmationRequired(
                    "The approval of '" + operation + "' was already used by a parallel"
                            + " call; nothing was changed by this one.",
                    Map.of("approval", Map.of("status", "consumed")));
        }
        return d;
    }

    /** Files the request with the provider. */
    private PendingApproval file(CibaClient client, ConfirmationRequest r, Caller caller, String issuer, String hint,
            String operation, String code, String key) {
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
        metrics.cibaFiled(r.system());
        LOG.infof("CIBA request %s for %s: %s %s (binding message %s%s, up to %d s, session %s)", requestId, hint,
                r.tool().name(), r.realm() == null ? "" : "realm " + r.realm(), binding == null ? "none" : binding,
                code == null ? "" : ", code " + code, budget, r.connectionId() == null ? "-" : r.connectionId());
        int interval = Math.max(1, started.interval());
        Object iss = caller.claim("iss");
        return new PendingApproval(key, started.authReqId(), requestId, code, binding, issuer, hint, caller.subject(),
                iss instanceof String s ? s : null, operation, r.system(), r.realm(),
                System.currentTimeMillis() + budget * 1000L, interval, System.currentTimeMillis());
    }

    /**
     * Polls until the device answered or {@code untilMillis} passed; "still waiting"
     * comes back as CONFIRMATION_REQUIRED with {@code waiting=true} in the details. An
     * approval is confirmed only when the ID token verifies and names the person who was
     * asked.
     */
    private Decision await(CibaClient client, PendingApproval p, long untilMillis) {
        Duration interval = Duration.ofSeconds(p.intervalSeconds());
        if (interval.compareTo(pollFloor) < 0) {
            interval = pollFloor;
        }
        while (true) {
            if (p.expired()) {
                decided(p, "timeout");
                return Decision.confirmationRequired("No approval for '" + p.operation() + "' arrived in time: "
                        + p.loginHint() + " was asked on their device" + bindingNote(p.bindingMessage())
                        + ". Nothing was changed; call again to send a new request when they are ready to approve.",
                        Map.of("approval", Map.of("status", "expired"), "howTo",
                                "Call again with the same arguments to send a new request to the user's device."));
            }
            if (System.currentTimeMillis() >= untilMillis) {
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
                    CibaIdentityVerifier.Identity who;
                    try {
                        who = verifiers.apply(client).verify(poll.idToken(), p);
                    }
                    catch (CibaException e) {
                        LOG.warnf("CIBA request %s: approval rejected: %s", p.requestId(), e.getMessage());
                        decided(p, "rejected");
                        return Decision.declined(e.getMessage(), Map.of("approval", Map.of("status", "rejected")));
                    }
                    LOG.infof("CIBA request %s approved by %s (sub %s)", p.requestId(), p.loginHint(), who.subject());
                    decided(p, "approved");
                    return Decision.confirmed();
                }
                case DENIED -> {
                    LOG.infof("CIBA request %s declined by %s", p.requestId(), p.loginHint());
                    decided(p, "declined");
                    return Decision.declined(
                            p.loginHint() + " declined '" + p.operation() + "' on their device"
                                    + bindingNote(p.bindingMessage()) + ".",
                            Map.of("approval", Map.of("status", "declined")));
                }
                case EXPIRED -> {
                    decided(p, "expired");
                    return Decision.confirmationRequired("The approval request for '" + p.operation()
                            + "' expired before " + p.loginHint() + " answered" + bindingNote(p.bindingMessage())
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
    private Decision awaiting(PendingApproval p, boolean fresh) {
        long left = Math.max(0, (p.expiresAt() - System.currentTimeMillis()) / 1000);
        Map<String, Object> approval = new LinkedHashMap<>();
        approval.put("status", fresh ? "requested" : "pending");
        approval.put("user", p.loginHint());
        if (p.bindingMessage() != null) {
            approval.put("bindingMessage", p.bindingMessage());
        }
        if (p.code() != null) {
            approval.put("code", p.code());
        }
        approval.put("expiresInSeconds", left);
        String code = p.code() == null ? "" : " The device asks for the number " + p.code() + ".";
        String message = fresh
                ? "'" + p.operation() + "' needs " + p.loginHint() + "'s approval on their device: a request"
                        + bindingNote(p.bindingMessage()) + " was sent." + code
                : "Still waiting for " + p.loginHint() + "'s approval of '" + p.operation() + "' on their device"
                        + bindingNote(p.bindingMessage()) + "." + code + " " + left + " s left.";
        String howTo = "Tell the user to approve the request on their device"
                + (p.code() == null ? "" : " and to enter the number " + p.code() + " when asked")
                + ", then call again with the same arguments to continue. Nothing has been changed yet.";
        return Decision.confirmationRequired(message, Map.of("approval", approval, "howTo", howTo));
    }

    private void decided(PendingApproval p, String outcome) {
        metrics.cibaDecision(outcome, p.system(), Duration.ofMillis(System.currentTimeMillis() - p.createdAt()));
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
