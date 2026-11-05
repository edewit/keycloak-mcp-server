package com.github.thomasdarimont.keycloak.mcp.confirm;

import java.util.Optional;

/** Asks the human a yes/no question through the MCP client's elicitation support. */
public interface Prompter {

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
     * @return the answer, or empty when the human dismissed the question, it timed out or
     * asking is not {@link #available()}
     */
    Optional<Boolean> askYesNo(String message);

}
