package com.github.thomasdarimont.keycloak.mcp.backend.ui;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Pattern;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;

import org.jboss.logging.Logger;

import com.github.thomasdarimont.keycloak.mcp.backend.config.DefaultTenant;
import com.github.thomasdarimont.keycloak.mcp.config.McpServerConfig;

import io.quarkus.oidc.OidcTenantConfig;
import io.quarkus.oidc.runtime.OidcTenantConfig.ApplicationType;
import io.quarkus.oidc.runtime.OidcTenantConfig.Roles;
import io.quarkus.oidc.runtime.OidcUtils;
import io.quarkus.vertx.http.runtime.CurrentVertxRequest;
import io.vertx.core.http.Cookie;
import io.vertx.ext.web.RoutingContext;

/**
 * The OIDC relying parties behind the management UI, one per identity provider the UI
 * offers ({@code kc-mcp.ui.idps.<alias>}, or the single {@link #DEFAULT_ALIAS} formed by
 * {@code kc-mcp.ui.issuer} and {@code client-id}). Each is a Quarkus {@code web-app}
 * tenant {@code kc-mcp-ui-<alias>} for the BFF paths: authorization code flow with PKCE
 * (S256), public client unless a secret is configured, the redirect URI is the login path
 * ({@code <server>/bff/login}, whatever query the sign-in button carried). The session
 * cookie is HttpOnly, Secure and holds only the id of a {@code UserSession}
 * ({@link UserSessionTokenStateManager}). Roles come from the access token, which is
 * verified too; expired ID tokens are renewed with the refresh token for up to the
 * provider's {@code session-age-extension} ({@code kc-mcp.ui.session-age-extension} by
 * default, the provider's SSO idle timeout); a browser request with
 * {@code X-Requested-With: JavaScript} that finds no session gets 499 instead of a
 * redirect, so the UI can show its sign-in buttons.
 * <p>
 * Which provider a request belongs to ({@link #resolve}): the {@code idp} query parameter
 * (the sign-in button), else the session or state cookie of a provider the browser
 * already has, else the first provider shown on the login page. Nothing is remembered
 * between sessions: a logout sends the browser back to {@code /ui/?idp=<alias>}, which
 * the page uses to offer that provider first, and that is all.
 * <p>
 * A provider with {@code hide-on-login-page=true} (as Keycloak calls it) never appears on
 * the login page, so a multi-tenant server does not advertise its tenants; its users sign
 * in through {@code /bff/login?idp=<alias>}, and once signed in the UI names it.
 */
@ApplicationScoped
public class UiTenant {

    public static final String TENANT_PREFIX = "kc-mcp-ui-";
    public static final String DEFAULT_ALIAS = "default";
    /** Where the UI is served. */
    public static final String UI_PATH = "/ui";
    /** The BFF: login, logout, me, check-session, api/*, backchannel-logout. */
    public static final String BFF_PATH = "/bff";
    public static final String LOGIN_PATH = BFF_PATH + "/login";
    public static final String LOGOUT_PATH = BFF_PATH + "/logout";
    public static final String API_PATH = BFF_PATH + "/api";
    /** Query parameter naming the provider, on the login path and on the UI's page. */
    public static final String IDP_PARAM = "idp";
    /** Browser requests that carry this header get status codes instead of redirects. */
    public static final String JAVASCRIPT_HEADER = "X-Requested-With";
    public static final String JAVASCRIPT_HEADER_VALUE = "JavaScript";

    private static final Logger LOG = Logger.getLogger(UiTenant.class);
    private static final Pattern ALIAS = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._~-]{0,99}");
    private static final String SESSION_COOKIE_PREFIX = OidcUtils.SESSION_COOKIE_NAME + "_" + TENANT_PREFIX;
    private static final String STATE_COOKIE_PREFIX = OidcUtils.STATE_COOKIE_NAME + "_" + TENANT_PREFIX;

    /** One identity provider of the UI. */
    public record Idp(String alias, String displayName, String issuer, String clientId, Optional<String> clientSecret,
            Duration sessionAgeExtension, boolean hidden) {
        public String tenantId() {
            return TENANT_PREFIX + alias;
        }

        public String describe() {
            return alias + " -> " + issuer + " as " + clientId
                    + (clientSecret.filter(v -> !v.isBlank()).isPresent() ? " (confidential, PKCE" : " (public, PKCE")
                    + ", sessions renewed for " + sessionAgeExtension + " past the ID token"
                    + (hidden ? ", hidden on the login page)" : ")");
        }
    }

    @Inject
    McpServerConfig config;
    @Inject
    Instance<CurrentVertxRequest> request;

    public static boolean isBffPath(String path) {
        return path.equals(BFF_PATH) || path.startsWith(BFF_PATH + "/");
    }

    public static boolean isApiPath(String path) {
        return path.equals(API_PATH) || path.startsWith(API_PATH + "/");
    }

    /** Whether a string can be a provider alias (and so a tenant id, a query value). */
    public static boolean isAlias(String value) {
        return value != null && ALIAS.matcher(value).matches();
    }

    /** {@code kc-mcp-ui-corp} -> {@code corp}; an unknown tenant id as is. */
    public static String aliasOf(String tenantId) {
        if (tenantId == null) {
            return DEFAULT_ALIAS;
        }
        return tenantId.startsWith(TENANT_PREFIX) ? tenantId.substring(TENANT_PREFIX.length()) : tenantId;
    }

    /**
     * The configured providers in configuration order, hidden ones included; the single
     * {@code default} one from the top-level settings when {@code kc-mcp.ui.idps} is
     * empty.
     */
    public List<Idp> idps() {
        Map<String, McpServerConfig.IdpSettings> named = config.ui().idps();
        List<Idp> out = new ArrayList<>();
        if (named.isEmpty()) {
            out.add(new Idp(DEFAULT_ALIAS, "Sign in", defaultIssuer(), config.ui().clientId(),
                    config.ui().clientSecret(), config.ui().sessionAgeExtension(), false));
            return out;
        }
        for (Map.Entry<String, McpServerConfig.IdpSettings> e : named.entrySet()) {
            McpServerConfig.IdpSettings s = e.getValue();
            out.add(new Idp(e.getKey(), s.displayName().filter(v -> !v.isBlank()).orElse(e.getKey()), s.issuer(),
                    s.clientId().filter(v -> !v.isBlank()).orElse(config.ui().clientId()),
                    s.clientSecret().filter(v -> !v.isBlank()).or(config.ui()::clientSecret),
                    s.sessionAgeExtension().orElse(config.ui().sessionAgeExtension()),
                    s.hideOnLoginPage().orElse(false)));
        }
        return out;
    }

    /** The providers the login page lists. */
    public List<Idp> visibleIdps() {
        return idps().stream().filter(i -> !i.hidden()).toList();
    }

    public Optional<Idp> idp(String alias) {
        return idps().stream().filter(i -> i.alias().equals(alias)).findFirst();
    }

    /**
     * The providers a token of {@code issuer} for one of {@code audiences} belongs to.
     */
    public List<Idp> idpsFor(String issuer, List<String> audiences) {
        return idps().stream().filter(i -> i.issuer().equals(issuer) && audiences.contains(i.clientId())).toList();
    }

    /**
     * The provider the UI's users log in at without named providers:
     * {@code kc-mcp.ui.issuer}, else {@code kc-mcp.admin.issuer}, else the server's own
     * auth realm.
     */
    public String defaultIssuer() {
        Optional<String> own = config.ui().issuer().filter(v -> !v.isBlank());
        if (own.isPresent()) {
            return own.get();
        }
        Optional<String> admin = config.admin().issuer().filter(v -> !v.isBlank());
        return admin.orElseGet(DefaultTenant::authServerUrl);
    }

    /** The tenant of the provider a BFF request belongs to. */
    public OidcTenantConfig resolve(RoutingContext context) {
        return config(idpFor(context));
    }

    /** The alias of the provider the current request belongs to, if in a request. */
    public Optional<String> currentAlias() {
        if (!request.isResolvable() || request.get().getCurrent() == null) {
            return Optional.empty();
        }
        return Optional.of(idpFor(request.get().getCurrent()).alias());
    }

    Idp idpFor(RoutingContext context) {
        List<Idp> all = idps();
        String requested = context.request().getParam(IDP_PARAM);
        if (isAlias(requested)) {
            Optional<Idp> found = all.stream().filter(i -> i.alias().equals(requested)).findFirst();
            if (found.isPresent()) {
                return found.get();
            }
            LOG.debugf("Unknown identity provider '%s' requested, using the browser's or the first", requested);
        }
        for (Cookie cookie : context.request().cookies()) {
            String alias = aliasOfCookie(cookie.getName());
            if (alias != null) {
                Optional<Idp> found = all.stream().filter(i -> i.alias().equals(alias)).findFirst();
                if (found.isPresent()) {
                    return found.get();
                }
            }
        }
        return all.stream().filter(i -> !i.hidden()).findFirst().orElse(all.get(0));
    }

    /**
     * The alias in a Quarkus OIDC cookie of a UI tenant: {@code q_session_kc-mcp-ui-corp}
     * (chunks end in {@code _chunk_N}), {@code q_auth_kc-mcp-ui-corp_<state>}; else
     * {@code null}.
     */
    static String aliasOfCookie(String name) {
        if (name.startsWith(SESSION_COOKIE_PREFIX)) {
            String rest = name.substring(SESSION_COOKIE_PREFIX.length());
            int chunk = rest.indexOf(OidcUtils.SESSION_COOKIE_CHUNK);
            return chunk > 0 ? rest.substring(0, chunk) : rest;
        }
        if (name.startsWith(STATE_COOKIE_PREFIX)) {
            String rest = name.substring(STATE_COOKIE_PREFIX.length());
            int state = rest.indexOf('_');
            return state > 0 ? rest.substring(0, state) : rest;
        }
        return null;
    }

    public OidcTenantConfig config(Idp idp) {
        var builder = OidcTenantConfig.builder()
            .tenantId(idp.tenantId())
            .applicationType(ApplicationType.WEB_APP)
            .authServerUrl(idp.issuer())
            .clientId(idp.clientId());
        idp.clientSecret().filter(v -> !v.isBlank()).ifPresent(builder::credentials);
        return builder.authentication()
            // the redirect URI is the login path alone, whatever query the sign-in button
            // carried (idp=<alias>); the callback finds its provider through the state
            // cookie
            .redirectPath(LOGIN_PATH)
            .pkceRequired(true)
            .cookieForceSecure(true)
            .javaScriptAutoRedirect(false)
            .verifyAccessToken(true)
            .sessionAgeExtension(idp.sessionAgeExtension())
            .end()
            .roles()
            .source(Roles.Source.accesstoken)
            .end()
            .token()
            .refreshExpired(true)
            .end()
            // the tokens reach the UserSessionTokenStateManager as they are; Quarkus
            // would
            // otherwise wrap them in a JWE under a key generated at startup, which no
            // other
            // instance and no restart could open. The store encrypts them at rest under
            // kc-mcp.storage.secret-key instead.
            .tokenStateManager()
            .encryptionRequired(false)
            .end()
            .logout()
            .path(LOGOUT_PATH)
            // back to the page with the provider named, so it offers that one first
            .postLogoutPath(UI_PATH + "/?" + IDP_PARAM + "=" + idp.alias())
            .end()
            .build();
    }
}
