package com.github.thomasdarimont.keycloak.mcp.backend.cli;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;

import io.quarkus.runtime.Quarkus;
import io.quarkus.runtime.annotations.QuarkusMain;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Option;
import picocli.CommandLine.ParameterException;
import picocli.CommandLine.ScopeType;
import picocli.CommandLine.Spec;
import picocli.CommandLine.Unmatched;

/**
 * The command line. It runs before Quarkus starts, because settings have to be in place
 * by the time Quarkus reads its configuration. They become system properties, so they
 * override the environment and the configuration files.
 * <p>
 * {@code build} is not here: the launch scripts run it, Quarkus handles it before this
 * class is reached.
 */
@QuarkusMain
@Command(name = "kcmcp", description = "Keycloak MCP Server",
        subcommands = { KcMcpMain.Start.class, KcMcpMain.StartDev.class })
public class KcMcpMain implements Callable<Integer> {

    static final int USAGE_ERROR = CommandLine.ExitCode.USAGE;

    @Spec
    CommandSpec spec;

    @Option(names = { "-h", "--help" }, usageHelp = true, scope = ScopeType.INHERIT, description = "Show this help.")
    boolean help;

    public static void main(String... args) {
        int exitCode = commandLine().execute(args);
        // a server that ran has already exited through Quarkus; dev mode has to return
        // from here to keep running
        if (exitCode != CommandLine.ExitCode.OK) {
            System.exit(exitCode);
        }
    }

    static CommandLine commandLine() {
        // an argument starting with @ is a value here, not a file of arguments
        return new CommandLine(new KcMcpMain()).setExpandAtFiles(false);
    }

    /** No command: the server only starts when asked to. */
    @Override
    public Integer call() {
        spec.commandLine().usage(spec.commandLine().getErr());
        return USAGE_ERROR;
    }

    abstract static class ServerCommand implements Callable<Integer> {

        @Spec
        CommandSpec spec;

        @Unmatched
        List<String> arguments = new ArrayList<>();

        @Override
        public Integer call() {
            Map<String, String> properties;
            try {
                properties = ConfigArguments.parse(arguments);
            }
            catch (IllegalArgumentException e) {
                throw new ParameterException(spec.commandLine(), e.getMessage(), e);
            }
            properties.forEach(System::setProperty);
            beforeStart();
            Quarkus.run();
            return CommandLine.ExitCode.OK;
        }

        void beforeStart() {
        }
    }

    @Command(name = "start",
            description = "Start the server. Settings: --kc-mcp.<name>=<value>, --quarkus.<name>=<value>.")
    static class Start extends ServerCommand {
    }

    @Command(name = "start-dev",
            description = "Start the server in development mode: profile local, startup checks warn, "
                    + "Keycloak at http://localhost:8080 unless a system is configured. Not for a server other people reach.")
    static class StartDev extends ServerCommand {

        @Override
        void beforeStart() {
            System.err.println(
                    "development mode (start-dev): profile local, startup checks warn, Keycloak at http://localhost:8080 "
                            + "unless a system is configured; use 'start' for a shared server");
            System.setProperty("kc-mcp.profile", "local");
            System.setProperty("kc-mcp.startup-check", "warn");
            System.setProperty("kc-mcp.dev-mode", "true");
        }
    }
}
