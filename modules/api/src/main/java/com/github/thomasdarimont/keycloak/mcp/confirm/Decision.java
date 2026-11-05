package com.github.thomasdarimont.keycloak.mcp.confirm;

/**
 * What a {@link Confirmer} answers.
 *
 * @param outcome what to do
 * @param message shown to the model (and so to the user) for DECLINED and
 * CONFIRMATION_REQUIRED, or {@code null} for the default wording
 */
public record Decision(Outcome outcome, String message) {

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

    public static Decision confirmed() {
        return CONFIRMED;
    }

    public static Decision declined(String message) {
        return new Decision(Outcome.DECLINED, message);
    }

    public static Decision confirmationRequired(String message) {
        return new Decision(Outcome.CONFIRMATION_REQUIRED, message);
    }

    public static Decision abstain() {
        return ABSTAIN;
    }

    public boolean isConfirmed() {
        return outcome == Outcome.CONFIRMED;
    }

}
