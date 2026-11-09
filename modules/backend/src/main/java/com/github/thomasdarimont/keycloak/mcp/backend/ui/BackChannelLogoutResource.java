package com.github.thomasdarimont.keycloak.mcp.backend.ui;

import java.util.Map;
import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.jboss.logging.Logger;

import com.github.thomasdarimont.keycloak.mcp.backend.metrics.KcMcpMetrics;
import com.github.thomasdarimont.keycloak.mcp.web.UserSessionStore;

/**
 * OpenID Connect back-channel logout for the management UI: the identity provider posts a
 * logout token when the user's session there ends (Keycloak: the client's <em>Backchannel
 * logout URL</em>, {@code <server>/bff/backchannel-logout}, with <em>session
 * required</em> on). {@link LogoutTokens} verifies it against the provider it names, then
 * every stored session with that {@code sid} (or, without one, of that user) is deleted
 * at once, on every instance sharing the database; the browser's next request finds no
 * session and the UI shows its sign-in buttons. One URL serves every provider: the
 * token's issuer and audience say which one it is.
 */
@Path(UiTenant.BFF_PATH)
public class BackChannelLogoutResource {

    public static final String PATH = UiTenant.BFF_PATH + "/backchannel-logout";

    private static final Logger LOG = Logger.getLogger(BackChannelLogoutResource.class);

    @Inject
    LogoutTokens tokens;
    @Inject
    UserSessionTokenStateManager sessions;
    @Inject
    KcMcpMetrics metrics;

    @POST
    @Path("backchannel-logout")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.APPLICATION_JSON)
    public Response logout(@FormParam("logout_token") String logoutToken) {
        LogoutTokens.LogoutToken token;
        try {
            token = tokens.verify(logoutToken);
        }
        catch (LogoutTokens.InvalidLogoutToken e) {
            LOG.warnf("Back-channel logout refused: %s", e.getMessage());
            metrics.backchannelLogout("invalid");
            return Response.status(400)
                .header("Cache-Control", "no-store")
                .entity(Map.of("error", "invalid_request", "message", e.getMessage()))
                .build();
        }
        UserSessionStore store = sessions.store();
        long ended = token.sid() != null && !token.sid().isBlank() ? store.deleteBySession(token.issuer(), token.sid())
                : store.deleteBySubject(token.issuer(), token.subject());
        metrics.backchannelLogout("ended");
        LOG.infof("Back-channel logout from %s: %d session(s) ended (%s)", token.idp().alias(), ended,
                token.sid() != null ? "sid " + token.sid() : "subject " + token.subject());
        return Response.ok().header("Cache-Control", "no-store").build();
    }
}
