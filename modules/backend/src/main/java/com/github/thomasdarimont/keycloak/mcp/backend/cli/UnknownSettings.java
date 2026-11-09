package com.github.thomasdarimont.keycloak.mcp.backend.cli;

import java.util.List;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;

import org.eclipse.microprofile.config.ConfigProvider;
import org.jboss.logging.Logger;

import com.github.thomasdarimont.keycloak.mcp.config.ValidationRun;

import io.quarkus.runtime.StartupEvent;

/**
 * Reports settings that do not exist. In {@code validate} all of them are problems. At
 * {@code start} only the environment can get this far: the command line has refused its
 * own already, and SmallRye ends the boot on an unknown name from a file, since it cannot
 * tell a variable meant for this server from any other, those are warnings.
 */
@ApplicationScoped
public class UnknownSettings {

    private static final Logger LOG = Logger.getLogger(UnknownSettings.class);

    static List<String> find() {
        return OptionCatalogue.unknown(ConfigProvider.getConfig().getPropertyNames(), System.getenv());
    }

    void onStart(@Observes StartupEvent event) {
        if (!ValidationRun.active()) {
            find().forEach(LOG::warn);
        }
    }
}
