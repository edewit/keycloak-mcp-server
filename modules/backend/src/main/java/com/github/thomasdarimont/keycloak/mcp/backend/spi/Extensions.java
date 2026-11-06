package com.github.thomasdarimont.keycloak.mcp.backend.spi;

import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.ServiceLoader;
import java.util.stream.Stream;
import jakarta.annotation.PreDestroy;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Any;
import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;

import org.jboss.logging.Logger;

import com.github.thomasdarimont.keycloak.mcp.config.McpServerConfig;
import com.github.thomasdarimont.keycloak.mcp.spi.Extension;
import com.github.thomasdarimont.keycloak.mcp.spi.ProviderConfig;

/**
 * Finds the implementations of an extension point ({@code ToolProvider},
 * {@code PromptProvider}, {@code AccessCheck}, {@code Confirmer}, {@code AuditListener}):
 * ServiceLoader entries on the class path and in the jars of the providers directory
 * ({@code kc-mcp.providers-dir}, like Keycloak's {@code providers/}), then CDI beans. A
 * class seen on both paths counts once.
 * <p>
 * The providers directory is read once at startup; a relative path is resolved against
 * the directory of the application jar ({@code quarkus-run.jar}) when the server runs
 * packaged, otherwise against the working directory. Jars found there are loaded by a
 * class loader whose parent is the application, so they see the api and the server
 * classes but are not visible to CDI: extensions in those jars register through
 * {@code META-INF/services}. JVM mode only.
 */
@ApplicationScoped
public class Extensions {

    private static final Logger LOG = Logger.getLogger(Extensions.class);

    private final Path dir;
    private final List<Path> jars;
    private final ClassLoader loader;
    private final URLClassLoader owned;
    private final Instance<Object> cdi;

    @Inject
    public Extensions(McpServerConfig config, @Any Instance<Object> cdi) {
        this(resolve(config.providersDir()), contextLoader(), cdi);
    }

    /**
     * @param dir providers directory, {@code null} for none
     * @param parent class loader for the service lookup and the parent of the jar loader
     * @param cdi {@code @Any Instance<Object>} for the bean lookup, {@code null} for none
     */
    public Extensions(Path dir, ClassLoader parent, Instance<Object> cdi) {
        this.dir = dir;
        this.cdi = cdi;
        this.jars = listJars(dir);
        if (jars.isEmpty()) {
            this.owned = null;
            this.loader = parent;
            if (dir != null) {
                LOG.debugf("No extension jars in %s", dir);
            }
        }
        else {
            this.owned = new URLClassLoader("kc-mcp-providers", urls(jars), parent);
            this.loader = owned;
            LOG.infof("Extensions directory %s: %s", dir, jars.stream().map(p -> p.getFileName().toString()).toList());
        }
    }

    /** Class path only, no providers directory and no CDI: tests and embedding. */
    public static Extensions classpath() {
        return new Extensions(null, contextLoader(), null);
    }

    /**
     * The implementations of {@code spi}, ServiceLoader entries first (class path, then
     * providers directory), then CDI beans; each class once.
     */
    public <T> List<T> discover(Class<T> spi) {
        Map<String, T> byClass = new LinkedHashMap<>();
        for (T t : ServiceLoader.load(spi, loader)) {
            byClass.putIfAbsent(t.getClass().getName(), t);
        }
        if (cdi != null) {
            for (Instance.Handle<T> h : cdi.select(spi).handles()) {
                byClass.computeIfAbsent(h.getBean().getBeanClass().getName(), k -> h.get());
            }
        }
        return List.copyOf(byClass.values());
    }

    /** The providers directory, {@code null} when none is configured. */
    public Path dir() {
        return dir;
    }

    /** The extension jars loaded from the providers directory. */
    public List<Path> jars() {
        return jars;
    }

    @PreDestroy
    void close() {
        if (owned != null) {
            try {
                owned.close();
            }
            catch (IOException e) {
                LOG.debugf(e, "Closing the extension class loader failed");
            }
        }
    }

    /**
     * A relative directory is resolved against the application home: the directory of the
     * jar when the class path is a single jar ({@code java -jar quarkus-run.jar}), else
     * the working directory.
     */
    public static Path resolve(String configured) {
        Path p = Path.of(configured.trim());
        if (p.isAbsolute()) {
            return p;
        }
        return appHome().resolve(p).toAbsolutePath().normalize();
    }

    static Path appHome() {
        String cp = System.getProperty("java.class.path", "");
        if (!cp.isBlank() && !cp.contains(File.pathSeparator) && cp.endsWith(".jar")) {
            Path parent = Path.of(cp).toAbsolutePath().getParent();
            if (parent != null) {
                return parent;
            }
        }
        return Path.of("").toAbsolutePath();
    }

    private static List<Path> listJars(Path dir) {
        if (dir == null || !Files.isDirectory(dir)) {
            return List.of();
        }
        try (Stream<Path> files = Files.list(dir)) {
            return files.filter(p -> p.getFileName().toString().endsWith(".jar") && Files.isRegularFile(p))
                .sorted()
                .toList();
        }
        catch (IOException e) {
            LOG.warnf(e, "Cannot read the extensions directory %s", dir);
            return List.of();
        }
    }

    private static URL[] urls(List<Path> jars) {
        List<URL> urls = new ArrayList<>();
        for (Path jar : jars) {
            try {
                urls.add(jar.toUri().toURL());
            }
            catch (MalformedURLException e) {
                throw new IllegalStateException(e);
            }
        }
        return urls.toArray(URL[]::new);
    }

    private static ClassLoader contextLoader() {
        ClassLoader cl = Thread.currentThread().getContextClassLoader();
        return cl != null ? cl : Extensions.class.getClassLoader();
    }

    /**
     * Whether a found extension takes part: not switched off with
     * {@code kc-mcp.spi.<id>.enabled=false}, and {@link Extension#isSupported} with the
     * current configuration. Every place that picks extensions asks here, so the rules
     * and the log lines are the same for all extension points.
     *
     * @param kind the extension point, for the log ({@code Confirmer}, {@code KeyVault},
     * ...)
     */
    public static boolean usable(Extension e, String kind, McpServerConfig config) {
        ProviderConfig settings = ProviderConfig.forExtension(e.id(), config.spi());
        if (!settings.getBoolean("enabled", true)) {
            LOG.infof("%s '%s' disabled by configuration", kind, e.id());
            return false;
        }
        boolean supported;
        try {
            supported = e.isSupported(config, settings);
        }
        catch (RuntimeException ex) {
            LOG.warnf(ex, "%s '%s' left out: isSupported failed: %s", kind, e.id(), ex.getMessage());
            return false;
        }
        if (!supported) {
            LOG.infof("%s '%s' left out: not supported with the current configuration", kind, e.id());
        }
        return supported;
    }
}
