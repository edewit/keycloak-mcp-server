package com.github.thomasdarimont.keycloak.mcp.spi;

import java.util.Map;
import java.util.Optional;

import com.github.thomasdarimont.keycloak.mcp.catalog.ToolSpec;

/**
 * Decides whether a destructive tool call may run. The built-in confirmer asks the human
 * through MCP elicitation when the client supports it and otherwise requires
 * {@code confirm: true}. Register your own ({@code @AutoService(Confirmer.class)} or a
 * CDI bean) to add a change ticket check, a four-eyes rule or an allow-list: custom
 * confirmers run first, lowest {@link #order()} first, and the chain stops at the first
 * decision that is not {@link Decision#ABSTAIN}; the built-in one runs last and never
 * abstains.
 */
public interface Confirmer extends Extension {

    Decision confirm(Request request);

    /**
     * @param tool the destructive tool about to run
     * @param system Keycloak system name, or {@code null} for the single system
     * @param realm target realm, or {@code null} for global tools
     * @param args validated arguments
     * @param confirmFlag whether the call carried {@code confirm: true}
     * @param caller who is acting; {@link Caller#NONE} on anonymous connections
     * @param prompter a way to ask the human through the MCP client, when it supports
     * elicitation
     */
    record Request(ToolSpec tool, String system, String realm, Map<String, Object> args, boolean confirmFlag,
            Caller caller, Prompter prompter) {

        public Request {
            args = Map.copyOf(args == null ? Map.of() : args);
            caller = caller == null ? Caller.NONE : caller;
            prompter = prompter == null ? Prompter.NONE : prompter;
        }

    }

    /** Asks the human a yes/no question through the MCP client's elicitation support. */
    interface Prompter {

        Prompter NONE = new Prompter() {
            @Override
            public boolean available() {
                return false;
            }

            @Override
            public Optional<Boolean> askYesNo(String message) {
                return Optional.empty();
            }
        };

        /** Whether the client can show a question to the human. */
        boolean available();

        /**
         * @return the answer, or empty when the human dismissed the question, it timed
         * out or asking is not {@link #available()}
         */
        Optional<Boolean> askYesNo(String message);

    }

    /**
     * @param outcome what to do
     * @param message shown to the model (and so to the user) for DECLINED and
     * CONFIRMATION_REQUIRED, or {@code null} for the default wording
     */
    record Decision(Outcome outcome, String message) {

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

}
