package com.github.thomasdarimont.keycloak.mcp.backend.http;

import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;

import com.github.thomasdarimont.keycloak.mcp.backend.config.PublicHostname;
import com.github.thomasdarimont.keycloak.mcp.config.McpServerConfig;

import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;

/**
 * Puts {@code kc-mcp.hostname} into the {@code resource_metadata} link of the bearer
 * challenge. Quarkus OIDC builds that link from the request's authority even for an
 * absolute {@code resource}, and it tells MCP clients where to start their login, so it
 * must not follow a {@code Host} header.
 */
@ApplicationScoped
public class PublicHostnameChallenge {

    private static final Pattern LINK = Pattern.compile("(resource_metadata=\")https?://[^/\"]+");

    private static final String WWW_AUTHENTICATE = "WWW-Authenticate";

    /** Ahead of the security routes, whose responses carry the challenge. */
    private static final int ORDER = -10_000;

    @Inject
    McpServerConfig config;

    void register(@Observes Router router) {
        PublicHostname.of(config.hostname())
            .ifPresent(origin -> router.route().order(ORDER).handler(ctx -> rewriteOnResponse(ctx, origin)));
    }

    private static void rewriteOnResponse(RoutingContext ctx, String origin) {
        ctx.addHeadersEndHandler(v -> {
            List<String> challenges = ctx.response().headers().getAll(WWW_AUTHENTICATE);
            if (!challenges.isEmpty()) {
                ctx.response()
                    .headers()
                    .set(WWW_AUTHENTICATE, challenges.stream().map(c -> rewrite(c, origin)).toList());
            }
        });
        ctx.next();
    }

    /** The challenge with the link's scheme and authority replaced. */
    static String rewrite(String challenge, String origin) {
        return LINK.matcher(challenge).replaceAll("$1" + Matcher.quoteReplacement(origin));
    }
}
