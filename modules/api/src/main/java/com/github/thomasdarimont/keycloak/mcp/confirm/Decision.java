package com.github.thomasdarimont.keycloak.mcp.confirm;

import java.util.Map;

/**
 * What a {@link Confirmer} answers.
 *
 * @param outcome what to do
 * @param message shown to the model (and so to the user) for DECLINED and
 * CONFIRMATION_REQUIRED, or {@code null} for the default wording
 * @param details extra fields for the tool result of DECLINED and CONFIRMATION_REQUIRED
 * (a {@code howTo} replaces the server's default hint; anything else is added as is), so
 * a confirmer can hand the model what the user needs, such as the number to enter on
 * their device
 */
public record Decision(Outcome outcome, String message, Map<String, Object> details) {

    public enum Outcome {
        /** Go ahead. */
        CONFIRMED,
        /** Refused; the tool does not run. */
        DECLINED,
        /** Nobody could decide: the caller must retry with {@code confirm: true}. */
        CONFIRMATION_REQUIRED,
        /** Not this confirmer's business; the next one decides. */
        ABSTAIN
    }

    public static final Decision CONFIRMED = new Decision(Outcome.CONFIRMED, null);

    public static final Decision DECLINED = new Decision(Outcome.DECLINED, null);

    public static final Decision CONFIRMATION_REQUIRED = new Decision(Outcome.CONFIRMATION_REQUIRED, null);

    public static final Decision ABSTAIN = new Decision(Outcome.ABSTAIN, null);

    public Decision {
        details = details == null ? Map.of() : Map.copyOf(details);
    }

    public Decision(Outcome outcome, String message) {
        this(outcome, message, Map.of());
    }

    public static Decision confirmed() {
        return CONFIRMED;
    }

    public static Decision declined(String message) {
        return new Decision(Outcome.DECLINED, message);
    }

    public static Decision declined(String message, Map<String, Object> details) {
        return new Decision(Outcome.DECLINED, message, details);
    }

    public static Decision confirmationRequired(String message) {
        return new Decision(Outcome.CONFIRMATION_REQUIRED, message);
    }

    public static Decision confirmationRequired(String message, Map<String, Object> details) {
        return new Decision(Outcome.CONFIRMATION_REQUIRED, message, details);
    }

    public static Decision abstain() {
        return ABSTAIN;
    }

    public boolean isConfirmed() {
        return outcome == Outcome.CONFIRMED;
    }
}
