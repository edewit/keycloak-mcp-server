package com.github.thomasdarimont.keycloak.mcp.confirm;

/**
 * A destructive operation waiting for the human's decision on their device (the CIBA
 * confirmer's two-step flow), as a {@link PendingApprovalStore} keeps it between the call
 * that filed the request and the call that collects the decision.
 *
 * @param key SHA-256 of MCP session, caller, issuer and operation: one approval per
 * session and operation
 * @param generation opaque id of this reservation: a later reservation of the same key
 * (after this one expired) has another, so an old caller can neither overwrite nor
 * consume it
 * @param authReqId the provider's {@code auth_req_id}; {@code null} while the slot is
 * only reserved
 * @param requestId short form of it for logs
 * @param code the number the device asks for (number matching), or {@code null}
 * @param bindingMessage what the device shows, or {@code null}
 * @param issuer the provider the request was filed with
 * @param loginHint who was asked
 * @param callerSubject the MCP caller's {@code sub}, or {@code null}
 * @param callerIssuer the issuer of the MCP caller's token, or {@code null}
 * @param operation what for, as shown to people
 * @param operationHash full SHA-256 (hex) of tool, system, realm and arguments; the
 * collecting call must present the same
 * @param system the Keycloak system the operation targets, or {@code null} for the single
 * system
 * @param realm the realm it targets, or {@code null} for a global tool
 * @param expiresAt epoch milliseconds after which the provider has forgotten the request
 * @param intervalSeconds the provider's polling interval
 * @param createdAt epoch milliseconds
 * @param claimedBy the collector currently polling the provider for it, or {@code null}
 * @param claimedUntil epoch milliseconds that claim lasts
 */
public record PendingApproval(String key, String generation, String authReqId, String requestId, String code,
        String bindingMessage, String issuer, String loginHint, String callerSubject, String callerIssuer,
        String operation, String operationHash, String system, String realm, long expiresAt, int intervalSeconds,
        long createdAt, String claimedBy, long claimedUntil) {

    /** A bare reservation: nothing filed yet. */
    public static PendingApproval reservation(String key, String generation, long until) {
        return new PendingApproval(key, generation, null, null, null, null, null, null, null, null, null, null, null,
                null, until, 0, System.currentTimeMillis(), null, 0);
    }

    public boolean filed() {
        return authReqId != null;
    }

    public boolean expired() {
        return expiresAt <= System.currentTimeMillis();
    }

    /** Whether another collector than {@code collector} holds a live claim. */
    public boolean claimedByOther(String collector, long now) {
        return claimedBy != null && !claimedBy.equals(collector) && claimedUntil > now;
    }

    public PendingApproval withClaim(String collector, long until) {
        return new PendingApproval(key, generation, authReqId, requestId, code, bindingMessage, issuer, loginHint,
                callerSubject, callerIssuer, operation, operationHash, system, realm, expiresAt, intervalSeconds,
                createdAt, collector, until);
    }
}
