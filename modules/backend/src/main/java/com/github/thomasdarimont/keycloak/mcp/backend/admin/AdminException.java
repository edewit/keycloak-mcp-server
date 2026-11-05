package com.github.thomasdarimont.keycloak.mcp.backend.admin;

/** A refusal of the admin API: HTTP status, error code and a message for the caller. */
public class AdminException extends RuntimeException {

    private final int status;
    private final String code;

    public AdminException(int status, String code, String message) {
        super(message);
        this.status = status;
        this.code = code;
    }

    public int status() {
        return status;
    }

    public String code() {
        return code;
    }
}
