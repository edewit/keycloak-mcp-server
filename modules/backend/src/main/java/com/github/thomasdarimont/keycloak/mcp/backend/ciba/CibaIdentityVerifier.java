package com.github.thomasdarimont.keycloak.mcp.backend.ciba;

import java.util.Optional;
import java.util.Set;

import org.eclipse.microprofile.jwt.JsonWebToken;

import com.github.thomasdarimont.keycloak.mcp.backend.ciba.CibaClient.CibaException;
import com.github.thomasdarimont.keycloak.mcp.confirm.PendingApproval;

import io.smallrye.jwt.auth.principal.DefaultJWTParser;
import io.smallrye.jwt.auth.principal.JWTAuthContextInfo;
import io.smallrye.jwt.auth.principal.ParseException;

/**
 * Checks who approved: the ID token the token endpoint returns on approval is verified
 * against the provider's keys (signature, issuer, the CIBA client as audience, expiry),
 * and its identity must be the person the request was filed for. When the MCP caller's
 * token comes from the same issuer, the subjects must match; otherwise the username or
 * email must match the login hint.
 */
public class CibaIdentityVerifier {

    /** Who the provider says approved. */
    public record Identity(String subject, String username, String email) {
        /**
         * @param tokenIssuer the issuer the approval's token carries; a caller whose own
         * token comes from it (or from the URL the provider is reached at) must be the
         * same subject
         */
        boolean matches(PendingApproval p, String tokenIssuer) {
            if (p.callerSubject() != null && p.callerIssuer() != null
                    && (p.callerIssuer().equals(p.issuer()) || p.callerIssuer().equals(tokenIssuer))) {
                return p.callerSubject().equals(subject);
            }
            return p.loginHint() != null && (p.loginHint().equalsIgnoreCase(username)
                    || p.loginHint().equalsIgnoreCase(email) || p.loginHint().equals(subject));
        }
    }

    private final String jwksUri;
    private final String issuer;
    private final String clientId;

    public CibaIdentityVerifier(String jwksUri, String issuer, String clientId) {
        this.jwksUri = jwksUri;
        this.issuer = issuer;
        this.clientId = clientId;
    }

    /**
     * @throws CibaException when the token is missing, not valid for this issuer and
     * client, or names somebody else
     */
    public Identity verify(String idToken, PendingApproval pending) {
        if (idToken == null || idToken.isBlank()) {
            throw new CibaException("The approval of " + issuer + " carries no ID token, so the approving identity"
                    + " cannot be verified; nothing was confirmed.");
        }
        JWTAuthContextInfo info = new JWTAuthContextInfo(jwksUri, issuer);
        info.setExpectedAudience(Set.of(clientId));
        info.setRequireNamedPrincipal(false);
        info.setClockSkew(60);
        JsonWebToken jwt;
        try {
            jwt = new DefaultJWTParser(info).parse(idToken);
        }
        catch (ParseException e) {
            throw new CibaException("The ID token of the approval is not valid for " + issuer + " and client "
                    + clientId + ": " + causes(e), e);
        }
        Identity identity = new Identity(jwt.getSubject(), claim(jwt, "preferred_username"), claim(jwt, "email"));
        if (!identity.matches(pending, issuer)) {
            throw new CibaException("The approval came from " + describe(identity) + ", not from " + pending.loginHint()
                    + (pending.callerSubject() != null ? " (sub " + pending.callerSubject() + ")" : "")
                    + "; nothing was confirmed.");
        }
        return identity;
    }

    /**
     * The message chain, since the parser wraps the actual reason (issuer, audience,
     * signature, expiry).
     */
    private static String causes(Throwable t) {
        StringBuilder b = new StringBuilder();
        for (Throwable c = t; c != null && c != c.getCause(); c = c.getCause()) {
            if (c.getMessage() != null && b.indexOf(c.getMessage()) < 0) {
                b.append(b.isEmpty() ? "" : "; ").append(c.getMessage());
            }
        }
        return b.toString();
    }

    private static String claim(JsonWebToken jwt, String name) {
        return Optional.ofNullable(jwt.<Object>getClaim(name)).map(Object::toString).orElse(null);
    }

    private static String describe(Identity i) {
        return i.username() != null ? i.username() : i.email() != null ? i.email() : "sub " + i.subject();
    }
}
