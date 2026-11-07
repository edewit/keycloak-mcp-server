package com.github.thomasdarimont.keycloak.mcp.backend.logging;

import java.util.logging.Level;

import org.jboss.logmanager.ExtLogRecord;
import org.jboss.logmanager.ExtLogRecord.FormatStyle;
import org.jboss.logmanager.formatters.PatternFormatter;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TokenRedactingLogFilterTest {

    static final String JWS = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJQc3VIMEVQNmJ2In0"
            + ".eyJzdWIiOiJhbGljZSIsImF1ZCI6Im1jcC1hZG1pbiJ9.tx74okGpIWE3bB_71ohne2tCRbWoKQdhQ1ECa0nQgC2RBir4ZOpHNc";

    static final String JWE = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0..aXYtdmFsdWUtMTI.Y2lwaGVydGV4dC1vZi10aGUtdG9rZW4"
            + ".dGFnLXZhbHVl";

    final TokenRedactingLogFilter filter = new TokenRedactingLogFilter();

    ExtLogRecord printf(String format, Object... params) {
        ExtLogRecord r = new ExtLogRecord(Level.WARNING, format, FormatStyle.PRINTF, getClass().getName());
        r.setParameters(params);
        return r;
    }

    @Test
    void theTokenOfAFailedVerificationIsTakenOutButTheKeyIdStays() {
        // what Quarkus OIDC logs when jose4j finds no key for the token
        ExtLogRecord r = printf("Token verification has failed: %s",
                "Unable to process JOSE object (cause: org.jose4j.lang.UnresolvableKeyException: JWK with kid"
                        + " 'PsuH0EP6bv' is not available): JsonWebSignature{\"alg\":\"RS256\",\"kid\" : \"PsuH0EP6bv\"}->"
                        + JWS);
        assertTrue(filter.isLoggable(r), "the line is kept");
        String out = r.getFormattedMessage();
        assertFalse(out.contains("eyJ"), out);
        assertFalse(out.contains("tx74okGp"), "no part of the signature: " + out);
        assertTrue(out.contains("kid 'PsuH0EP6bv' is not available"), out);
        assertTrue(out.endsWith("->***"), out);
    }

    @Test
    void encryptedTokensAndBearerHeadersAreTakenOutToo() {
        ExtLogRecord r = printf("auth_req_id %s, header Authorization: Bearer %s", JWE, "opaque-token-value-123");
        filter.isLoggable(r);
        assertEquals("auth_req_id ***, header Authorization: Bearer ***", r.getFormattedMessage());
    }

    @Test
    void aLineWithoutTokensIsLeftAlone() {
        ExtLogRecord r = printf("CIBA request %s approved by %s", "…kZNggt57tAO8", "alice");
        filter.isLoggable(r);
        assertEquals("CIBA request …kZNggt57tAO8 approved by alice", r.getFormattedMessage());
        assertEquals(FormatStyle.PRINTF, r.getFormatStyle(), "not rewritten");
    }

    @Test
    void aLoggedExceptionWithATokenInItsMessageOrCauseIsRedactedInTheStackTrace() {
        // what Quarkus OIDC logs at debug level with the exception attached: jose4j's
        // message holds the token
        Exception cause = new IllegalStateException("JWT (claims->{\"sub\":\"alice\"}) " + JWS + " rejected");
        Exception thrown = new RuntimeException("Token verification failed: Bearer opaque-token-value-123", cause);
        thrown.addSuppressed(new IllegalArgumentException("also saw " + JWE));
        ExtLogRecord r = printf("authentication failed for %s", "alice");
        r.setThrown(thrown);
        filter.isLoggable(r);

        String rendered = new PatternFormatter("%m%n%e").format(r);
        assertFalse(rendered.contains("eyJ"), rendered);
        assertFalse(rendered.contains("opaque-token-value-123"), rendered);
        assertTrue(rendered.contains("java.lang.RuntimeException: Token verification failed: Bearer ***"), rendered);
        assertTrue(
                rendered.contains(
                        "Caused by: java.lang.IllegalStateException: JWT (claims->{\"sub\":\"alice\"}) *** rejected"),
                rendered);
        assertTrue(rendered.contains("Suppressed: java.lang.IllegalArgumentException: also saw ***"), rendered);
        assertTrue(rendered.contains("TokenRedactingLogFilterTest"), "the stack frames stay: " + rendered);
    }

    @Test
    void anExceptionWithoutTokensIsLeftAsItIs() {
        Exception thrown = new IllegalStateException("plain failure");
        ExtLogRecord r = printf("failed");
        r.setThrown(thrown);
        filter.isLoggable(r);
        assertSame(thrown, r.getThrown());
    }

    @Test
    void aLongLineIsNotCut() {
        String tail = "x".repeat(2000);
        ExtLogRecord r = printf("%s %s", JWS, tail);
        filter.isLoggable(r);
        assertEquals("*** " + tail, r.getFormattedMessage());
    }
}
