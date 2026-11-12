package com.github.thomasdarimont.keycloak.mcp.backend.guard;

import org.junit.jupiter.api.Test;

import io.opentelemetry.api.trace.Span;
import io.opentelemetry.sdk.trace.SdkTracerProvider;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

/** The audit event takes the ids of the span a call runs in, and none outside a trace. */
class AuditLogTraceTest {

    @Test
    void idsOfARecordingSpan() {
        try (SdkTracerProvider tracers = SdkTracerProvider.builder().build()) {
            Span span = tracers.get("test").spanBuilder("tool call").startSpan();
            try {
                assertEquals(span.getSpanContext().getTraceId(), AuditLog.traceId(span));
                assertEquals(span.getSpanContext().getSpanId(), AuditLog.spanId(span));
                assertEquals(32, AuditLog.traceId(span).length());
                assertEquals(16, AuditLog.spanId(span).length());
            }
            finally {
                span.end();
            }
        }
    }

    @Test
    void nothingOutsideATrace() {
        assertNull(AuditLog.traceId(Span.getInvalid()));
        assertNull(AuditLog.spanId(Span.getInvalid()));
    }
}
