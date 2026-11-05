package com.github.thomasdarimont.keycloak.mcp.server.spi;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.github.thomasdarimont.keycloak.mcp.spi.AuditListener;
import com.github.thomasdarimont.keycloak.mcp.spi.ToolProvider;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ExtensionsTest {

    private static final String SERVICE = "META-INF/services/" + AuditListener.class.getName();

    @Test
    void loadsServicesFromJarsInTheProvidersDirectory(@TempDir Path dir) throws IOException {
        jar(dir.resolve("acme.jar"), SERVICE, JarOnlyListener.class.getName());

        Extensions ext = new Extensions(dir, getClass().getClassLoader(), null);

        assertEquals(List.of(dir.resolve("acme.jar")), ext.jars());
        List<AuditListener> found = ext.discover(AuditListener.class);
        assertTrue(found.stream().anyMatch(l -> l instanceof JarOnlyListener), found.toString());
        // the class path entries are still there
        assertTrue(found.stream().anyMatch(l -> l instanceof RecordingAuditListener), found.toString());
        ext.close();
    }

    @Test
    void aClassNamedOnBothPathsCountsOnce(@TempDir Path dir) throws IOException {
        jar(dir.resolve("dup.jar"), SERVICE, RecordingAuditListener.class.getName());

        List<AuditListener> found = new Extensions(dir, getClass().getClassLoader(), null)
            .discover(AuditListener.class);

        assertEquals(1, found.stream().filter(l -> l instanceof RecordingAuditListener).count(), found.toString());
    }

    @Test
    void missingDirectoryAndNonJarsAreIgnored(@TempDir Path dir) throws IOException {
        Files.writeString(dir.resolve("README.txt"), "not a jar");

        assertTrue(new Extensions(dir.resolve("nope"), getClass().getClassLoader(), null).jars().isEmpty());
        assertTrue(new Extensions(dir, getClass().getClassLoader(), null).jars().isEmpty());
        assertFalse(Extensions.classpath().discover(ToolProvider.class).isEmpty());
    }

    @Test
    void relativeDirectoryResolvesAgainstTheApplicationHome() {
        Path p = Extensions.resolve("providers");
        assertTrue(p.isAbsolute());
        assertEquals("providers", p.getFileName().toString());
        assertEquals(Path.of("/opt/kc-mcp/providers"), Extensions.resolve("/opt/kc-mcp/providers"));
    }

    private static void jar(Path file, String entry, String content) throws IOException {
        try (OutputStream out = Files.newOutputStream(file); JarOutputStream jar = new JarOutputStream(out)) {
            jar.putNextEntry(new JarEntry(entry));
            jar.write((content + "\n").getBytes(StandardCharsets.UTF_8));
            jar.closeEntry();
        }
    }
}
