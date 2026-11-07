package com.github.thomasdarimont.keycloak.mcp.storage.audit;

import java.util.Arrays;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import org.jboss.logging.Logger;

import com.github.thomasdarimont.keycloak.mcp.audit.AuditEvent;
import com.github.thomasdarimont.keycloak.mcp.audit.AuditListener;
import com.github.thomasdarimont.keycloak.mcp.audit.AuditScrubber;
import com.github.thomasdarimont.keycloak.mcp.config.McpServerConfig;
import com.github.thomasdarimont.keycloak.mcp.spi.ProviderConfig;
import com.github.thomasdarimont.keycloak.mcp.storage.StorageEnabledInterceptorFactory;
import com.github.thomasdarimont.keycloak.mcp.storage.crypto.StorageCrypto;

import io.quarkus.arc.lookup.LookupIfProperty;

/**
 * The {@link AuditScrubber} of the storage module, configured under
 * {@code kc-mcp.spi.pii-audit-scrubber.*}: {@code pii} is {@code keep} (default, nothing
 * happens), {@code pseudonymize} or {@code drop}; {@code pii-args} names the personal
 * arguments (default {@value #DEFAULT_PII_ARGS}; {@code id} counts too on user tools,
 * whose ids may be usernames); {@code targets} lists the listener ids it applies to
 * (default {@code db-audit}, the rows that persist; {@code console} for the opposite, a
 * console without names while the database keeps the full record; {@code *} for every
 * listener). Pseudonymizing replaces the caller's name and the personal argument values
 * by a keyed hash ({@link StorageCrypto#pseudonym}, under
 * {@code kc-mcp.storage.secret-key}), so one person stays recognisable across records,
 * and drops the message, which may echo usernames; dropping removes them. The caller's
 * subject (an opaque id), realm and roles and the outcome stay in every mode.
 */
@ApplicationScoped
@LookupIfProperty(name = StorageEnabledInterceptorFactory.ENABLED, stringValue = "true")
public class PiiAuditScrubber implements AuditScrubber {

    public static final String ID = "pii-audit-scrubber";

    /** Argument names treated as personal data by default. */
    public static final String DEFAULT_PII_ARGS = "username,email,firstName,lastName,search,userId,user,attributes";

    private static final Logger LOG = Logger.getLogger(PiiAuditScrubber.class);

    /** What happens to personal data. */
    public enum Policy {
        KEEP, PSEUDONYMIZE, DROP;

        static Policy parse(String value) {
            return switch (value.trim().toLowerCase(Locale.ROOT)) {
                case "keep" -> KEEP;
                case "pseudonymize", "pseudonymise", "hash" -> PSEUDONYMIZE;
                case "drop", "remove" -> DROP;
                default -> throw new IllegalArgumentException(
                        "kc-mcp.spi.pii-audit-scrubber.pii must be keep, pseudonymize or drop, not '" + value + "'");
            };
        }
    }

    private final Policy policy;
    private final Set<String> piiArgs;
    private final Set<String> targets;
    private final StorageCrypto crypto;

    @Inject
    public PiiAuditScrubber(McpServerConfig serverConfig, StorageCrypto crypto) {
        this(ProviderConfig.forExtension(ID, serverConfig.spi()), crypto);
    }

    /**
     * A HMAC key of the scrubber's own, so a storage key rotation keeps the pseudonyms
     * stable.
     */
    public static final String PSEUDONYM_KEY = "pseudonym-key";

    PiiAuditScrubber(ProviderConfig config, StorageCrypto crypto) {
        this(Policy.parse(config.get("pii", "keep")), config.get("pii-args", DEFAULT_PII_ARGS),
                config.get("targets", DatabaseAuditListener.ID),
                config.get(PSEUDONYM_KEY).map(StorageCrypto::new).orElse(crypto));
    }

    /**
     * @param piiArgs comma separated argument names
     * @param targets comma separated listener ids, {@code *} for all
     */
    public PiiAuditScrubber(Policy policy, String piiArgs, String targets, StorageCrypto crypto) {
        this.policy = policy;
        this.piiArgs = csv(piiArgs).stream()
            .map(v -> v.toLowerCase(Locale.ROOT))
            .collect(Collectors.toUnmodifiableSet());
        this.targets = csv(targets);
        this.crypto = crypto;
        if (policy != Policy.KEEP) {
            LOG.infof("Audit events for %s %s personal data (%s)",
                    this.targets.contains("*") ? "every listener" : this.targets,
                    policy == Policy.DROP ? "drop" : "pseudonymize", String.join(", ", this.piiArgs));
        }
    }

    @Override
    public String id() {
        return ID;
    }

    @Override
    public String displayName() {
        return "Personal data scrubber";
    }

    @Override
    public String description() {
        return "personal data in audit events: " + policy.name().toLowerCase(Locale.ROOT) + " for " + targets;
    }

    public Policy policy() {
        return policy;
    }

    /** Whether the scrubber touches events for this listener. */
    public boolean applies(AuditListener target) {
        return policy != Policy.KEEP && (targets.contains("*") || targets.contains(target.id()));
    }

    @Override
    public AuditEvent scrub(AuditEvent event, AuditListener target) {
        if (!applies(target)) {
            return event;
        }
        boolean userTool = event.tool() != null && event.tool().contains("_user_");
        AuditEvent scrubbed = event
            .mapArgs(name -> piiArgs.contains(name.toLowerCase(Locale.ROOT)) || (userTool && name.equals("id")),
                    value -> policy == Policy.DROP ? "***" : crypto.pseudonym(String.valueOf(value)))
            .withMessage(null);
        if (event.caller().isAnonymous()) {
            return scrubbed;
        }
        String name = policy == Policy.DROP ? null : crypto.pseudonym(event.caller().name());
        return scrubbed.withCaller(event.caller().withoutClaims().withName(name));
    }

    private static Set<String> csv(String value) {
        return Arrays.stream(value.split(","))
            .map(String::trim)
            .filter(v -> !v.isEmpty())
            .collect(Collectors.toUnmodifiableSet());
    }
}
