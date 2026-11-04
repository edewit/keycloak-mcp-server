package org.keycloak.mcp.spi;

import java.util.Map;

import org.keycloak.mcp.catalog.ToolSpec;
import org.keycloak.mcp.guard.GrantedRoles;
import org.keycloak.mcp.keycloak.KeycloakAdmin;

/**
 * Additional access predicate, evaluated per call after the static policy, realm
 * allow-list and role checks and before confirmation. Attach to one tool with
 * {@code ToolSpec.builder(...).access(check)} or contribute globally from
 * {@link ToolProvider#accessChecks(ToolProviderContext)} (or as a CDI bean). Checks run
 * on the handler's virtual thread and may call Keycloak; only the {@code tools/list}
 * filter must not block.
 */
@FunctionalInterface
public interface AccessCheck {

    Decision check(Context context);

    /**
     * @param tool the tool about to run
     * @param system Keycloak system name ({@code null} in single-system unit tests)
     * @param realm resolved target realm ({@code null} for global tools)
     * @param args validated arguments
     * @param roles what the token behind this call can do: the server's own, or the
     * caller's under delegation
     * @param caller who is acting through the connection
     * @param keycloak the admin client the call will run with (the caller's own under
     * delegation); {@code null} in unit tests
     */
    record Context(ToolSpec tool, String system, String realm, Map<String, Object> args, GrantedRoles roles,
            Caller caller, KeycloakAdmin keycloak) {

        public Context(ToolSpec tool, String system, String realm, Map<String, Object> args, GrantedRoles roles,
                Caller caller) {
            this(tool, system, realm, args, roles, caller, null);
        }

        public Context(ToolSpec tool, String realm, Map<String, Object> args, GrantedRoles roles, Caller caller) {
            this(tool, null, realm, args, roles, caller, null);
        }

        public String arg(String name) {
            Object v = args.get(name);
            return v == null ? null : String.valueOf(v);
        }
    }

    /**
     * {@code allowed} or a denial with an error code (defaults to {@code access_denied})
     * and a message.
     */
    record Decision(boolean allowed, String code, String message) {

        public static final Decision ALLOW = new Decision(true, null, null);

        public static Decision allow() {
            return ALLOW;
        }

        public static Decision deny(String message) {
            return new Decision(false, "access_denied", message);
        }

        public static Decision deny(String code, String message) {
            return new Decision(false, code, message);
        }
    }
}
