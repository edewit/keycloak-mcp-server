package com.github.thomasdarimont.keycloak.mcp.config;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * The {@code validate} command boots the server to run its startup checks. In that run a
 * check that fails is collected here instead of stopping the start, so that all problems
 * are reported at once, and startup work that changes data is skipped.
 */
public final class ValidationRun {

    /** System property the {@code validate} command sets. */
    public static final String PROPERTY = "kcmcp.validate";

    private static final List<String> PROBLEMS = new CopyOnWriteArrayList<>();

    private ValidationRun() {
    }

    public static boolean active() {
        return Boolean.getBoolean(PROPERTY);
    }

    /** Runs a startup check: as is normally, collecting its failure in a validation. */
    public static void guard(Runnable check) {
        if (!active()) {
            check.run();
            return;
        }
        try {
            check.run();
        }
        catch (RuntimeException e) {
            add(message(e));
        }
    }

    public static void add(String problem) {
        PROBLEMS.add(problem);
    }

    public static List<String> problems() {
        return List.copyOf(PROBLEMS);
    }

    /** The message of the innermost cause, which is the one that names the setting. */
    public static String message(Throwable e) {
        Throwable root = e;
        while (root.getCause() != null && root.getCause() != root) {
            root = root.getCause();
        }
        return root.getMessage() != null ? root.getMessage() : root.toString();
    }
}
