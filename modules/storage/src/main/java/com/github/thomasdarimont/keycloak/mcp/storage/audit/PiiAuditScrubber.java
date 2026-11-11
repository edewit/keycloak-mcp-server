package com.github.thomasdarimont.keycloak.mcp.storage.audit;

import java.util.Collection;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import org.jboss.logging.Logger;

import com.github.thomasdarimont.keycloak.mcp.audit.AuditEvent;
import com.github.thomasdarimont.keycloak.mcp.audit.AuditListener;
import com.github.thomasdarimont.keycloak.mcp.audit.AuditScrubber;
import com.github.thomasdarimont.keycloak.mcp.config.SettingValues;
import com.github.thomasdarimont.keycloak.mcp.spi.ConfigHint;
import com.github.thomasdarimont.keycloak.mcp.spi.ConfigProperty;
import com.github.thomasdarimont.keycloak.mcp.spi.ConfigSpec;
import com.github.thomasdarimont.keycloak.mcp.spi.ProviderConfig;
import com.github.thomasdarimont.keycloak.mcp.storage.StorageEnabledInterceptorFactory;
import com.github.thomasdarimont.keycloak.mcp.storage.crypto.StorageCrypto;

import io.quarkus.arc.lookup.LookupIfProperty;

/**
 * The {@link AuditScrubber} of the storage module, configured under
 * {@code kc-mcp.spi.audit-scrubber.pii.*}: {@code mode} is {@code keep} (default, nothing
 * happens), {@code pseudonymize} or {@code drop}; {@code args} names the personal
 * arguments (default {@value #DEFAULT_PII_ARGS}; {@code id} counts too on user tools,
 * whose ids may be usernames); {@code targets} lists the listener ids it applies to
 * (default {@code db}, the rows that persist; {@code console} for the opposite, a console
 * without names while the database keeps the full record; {@code *} for every listener).
 * Pseudonymizing replaces the caller's name and the personal argument values by a keyed
 * hash ({@link StorageCrypto#pseudonym}, under {@code kc-mcp.storage.secret-key}), so one
 * person stays recognisable across records, and drops the message, which may echo
 * usernames; dropping removes them. The caller's subject (an opaque id), realm and roles
 * and the outcome stay in every mode.
 */
@ApplicationScoped
@LookupIfProperty(name = StorageEnabledInterceptorFactory.ENABLED, stringValue = "true")
public class PiiAuditScrubber implements AuditScrubber {

    public static final String ID = "pii";

    /** Argument names treated as personal data by default. */
    public static final String DEFAULT_PII_ARGS = "username,email,firstName,lastName,search,userId,user,attributes";

    private static final Logger LOG = Logger.getLogger(PiiAuditScrubber.class);

    /** What happens to personal data. */
    public enum Policy {
        KEEP, PSEUDONYMIZE, DROP
    }

    public static final ConfigProperty MODE = ConfigProperty.choice("mode", Policy.class)
        .withDefault("keep")
        .withLabel("Mode")
        .withDescription("What happens to personal data: keep (nothing happens), pseudonymize (keyed hash) or drop.");

    public static final ConfigProperty ARGS = ConfigProperty.list("args")
        .withDefault(DEFAULT_PII_ARGS)
        .withLabel("Personal arguments")
        .withDescription("Tool argument names treated as personal data; 'id' counts too on user tools.");

    public static final ConfigProperty TARGETS = ConfigProperty.list("targets")
        .withDefault(DatabaseAuditListener.ID)
        .withLabel("Listeners")
        .withDescription("Audit listener ids the scrubber applies to, '*' for every listener.");

    /**
     * A HMAC key of the scrubber's own, so a storage key rotation keeps the pseudonyms
     * stable.
     */
    public static final ConfigProperty PSEUDONYM_KEY = ConfigProperty.string("pseudonym-key")
        .asConfidential()
        .withLabel("Pseudonym key")
        .withDescription(
                "HMAC key of the pseudonyms; defaults to kc-mcp.storage.secret-key, which a rotation changes.");

    public static final ConfigSpec CONFIG_SPEC = ConfigSpec.of(MODE, ARGS, TARGETS, PSEUDONYM_KEY)
        .withHints(ConfigHint.when(ARGS.name()).is(MODE.name(), "pseudonymize", "drop"),
                ConfigHint.when(TARGETS.name()).is(MODE.name(), "pseudonymize", "drop"),
                ConfigHint.when(PSEUDONYM_KEY.name()).is(MODE.name(), "pseudonymize"));

    private final StorageCrypto storageCrypto;
    private Policy policy = Policy.KEEP;
    private Set<String> piiArgs = Set.of();
    private Set<String> targets = Set.of();
    private StorageCrypto crypto;

    /** Does nothing until {@link #configure} hands it its settings. */
    @Inject
    public PiiAuditScrubber(StorageCrypto crypto) {
        this.storageCrypto = crypto;
        this.crypto = crypto;
    }

    /** Configured with these settings, for tests. */
    PiiAuditScrubber(ProviderConfig config, StorageCrypto crypto) {
        this(crypto);
        configure(config);
    }

    /**
     * @param piiArgs comma separated argument names
     * @param targets comma separated listener ids, {@code *} for all
     */
    public PiiAuditScrubber(Policy policy, String piiArgs, String targets, StorageCrypto crypto) {
        this(crypto);
        apply(policy, SettingValues.csv(piiArgs), SettingValues.csv(targets), crypto);
    }

    @Override
    public ConfigSpec configSpec() {
        return CONFIG_SPEC;
    }

    @Override
    public void configure(ProviderConfig config) {
        apply(config.readEnum(MODE, Policy.class), config.readList(ARGS), config.readList(TARGETS),
                Optional.ofNullable(config.readString(PSEUDONYM_KEY)).map(StorageCrypto::new).orElse(storageCrypto));
    }

    private void apply(Policy policy, Collection<String> piiArgs, Collection<String> targets, StorageCrypto crypto) {
        this.policy = policy;
        this.piiArgs = piiArgs.stream().map(v -> v.toLowerCase(Locale.ROOT)).collect(Collectors.toUnmodifiableSet());
        this.targets = Set.copyOf(targets);
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

}
