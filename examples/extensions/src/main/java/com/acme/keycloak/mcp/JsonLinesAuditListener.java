package com.acme.keycloak.mcp;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Map;
import java.util.concurrent.locks.ReentrantLock;

import com.github.thomasdarimont.keycloak.mcp.audit.AuditEvent;
import com.github.thomasdarimont.keycloak.mcp.audit.AuditListener;
import com.github.thomasdarimont.keycloak.mcp.spi.ProviderConfig;
import com.google.auto.service.AutoService;

import io.vertx.core.json.JsonObject;

/**
 * Extension point {@link AuditListener}: one JSON line per finished tool call, appended to
 * a file ({@code KC_MCP_SPI_ACME_AUDIT_FILE}, default {@code acme-audit.jsonl}). Listeners
 * run on the handler's thread; a slow sink would hand off to its own executor. Arguments
 * arrive with secrets redacted; {@link NoEmailScrubber} removes e-mail addresses before.
 */
@AutoService(AuditListener.class)
public class JsonLinesAuditListener implements AuditListener {

    private final Path file;
    private final ReentrantLock lock = new ReentrantLock();

    public JsonLinesAuditListener() {
        this(Path.of(ProviderConfig.forExtension("acme-audit", Map.of()).get("file", "acme-audit.jsonl")));
    }

    JsonLinesAuditListener(Path file) {
        this.file = file;
    }

    @Override
    public String id() {
        return "acme-audit";
    }

    @Override
    public String description() {
        return "JSON lines in " + file;
    }

    @Override
    public void onToolCall(AuditEvent e) {
        JsonObject line = new JsonObject().put("at", e.at().toString())
            .put("tool", e.tool())
            .put("level", e.level() == null ? null : e.level().name())
            .put("system", e.system())
            .put("realm", e.realm())
            .put("outcome", e.outcome())
            .put("message", e.message())
            .put("caller", e.caller().name())
            .put("callerSubject", e.caller().subject())
            .put("delegated", e.caller().delegated())
            .put("client", e.clientName())
            .put("args", new JsonObject(e.args()))
            .put("durationMs", e.duration() == null ? null : e.duration().toMillis());
        lock.lock();
        try {
            Files.writeString(file, line.encode() + System.lineSeparator(), StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        }
        catch (IOException ex) {
            throw new IllegalStateException("Cannot append to " + file + ": " + ex.getMessage(), ex);
        }
        finally {
            lock.unlock();
        }
    }
}
