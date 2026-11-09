package com.github.thomasdarimont.keycloak.mcp.backend;

import java.io.IOException;
import java.net.URI;
import java.net.URLDecoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import jakarta.inject.Inject;

import org.junit.jupiter.api.Test;

import com.github.thomasdarimont.keycloak.mcp.backend.ui.UiTenant;
import com.github.thomasdarimont.keycloak.mcp.backend.ui.UserSessionTokenStateManager;
import com.github.thomasdarimont.keycloak.mcp.storage.web.UserSessionEntity;
import com.github.thomasdarimont.keycloak.mcp.web.UserSession;

import io.quarkus.narayana.jta.QuarkusTransaction;
import io.quarkus.test.common.QuarkusTestResource;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.RestAssured;
import io.restassured.response.Response;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.hasItems;
import static org.hamcrest.Matchers.hasKey;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The management UI's BFF against a real Keycloak: the authorization code flow with PKCE
 * as a browser would run it (login form posted by hand), the session row in the database
 * with encrypted tokens and an opaque cookie, roles from the access token, the session
 * check, the RP-initiated logout and Keycloak's back-channel logout. Run with
 * {@code ./mvnw verify -DskipITs=false}.
 */
@QuarkusTest
@QuarkusTestResource(value = UiTestResource.class, restrictToAnnotatedClass = true)
class UiLoginIT {

    private static final Pattern FORM_ACTION = Pattern.compile("action=\"([^\"]+)\"");
    private static final HttpClient HTTP = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build();

    @Inject
    UserSessionTokenStateManager sessions;

    @Test
    void anonymousBrowserSeesTheProvidersAndNoRedirects() {
        given().get("/bff/me")
            .then()
            .statusCode(200)
            .body("authenticated", equalTo(false))
            .body("idps.alias", hasItems("demo", "second"))
            .body("idps.find { it.alias == 'demo' }.displayName", equalTo("Demo realm"))
            .body("idps.find { it.alias == 'second' }.loginPath", equalTo("/bff/login?idp=second"))
            .body("idps.alias", not(hasItem("hidden")));
        // the return from a logout names the provider that was used: offered first; a
        // hidden
        // provider stays off the page even then, its users sign in through the login path
        given().get("/bff/me?idp=second").then().statusCode(200).body("suggestedIdp", equalTo("second"));
        given().get("/bff/me?idp=hidden")
            .then()
            .statusCode(200)
            .body("$", not(hasKey("suggestedIdp")))
            .body("idps.alias", not(hasItem("hidden")));
        given().redirects()
            .follow(false)
            .get("/bff/login?idp=hidden")
            .then()
            .statusCode(302)
            .header("Location", containsString("client_id=keycloak-mcp-ui-2"));
        given().get("/bff/me?idp=nope").then().statusCode(200).body("$", not(hasKey("suggestedIdp")));
        // the UI's own requests get a status code, not a redirect to the provider
        given().header(UiTenant.JAVASCRIPT_HEADER, UiTenant.JAVASCRIPT_HEADER_VALUE)
            .get("/bff/api/systems")
            .then()
            .statusCode(499);
        // the SPA: any route gets the page, files keep their paths
        given().redirects().follow(false).get("/ui").then().statusCode(302).header("Location", equalTo("/ui/"));
        given().get("/ui/")
            .then()
            .statusCode(200)
            .header("Cache-Control", equalTo("no-cache"))
            .body(containsString("<kc-mcp-app>"));
        given().get("/ui/systems/acme").then().statusCode(200).body(containsString("<kc-mcp-app>"));
        given().get("/ui/missing.css").then().statusCode(404);
    }

    @Test
    void realmAdminSignsInWithPkceAndCallsTheApi() {
        Browser alice = Browser.login("demo", "alice", "alice");
        assertTrue(alice.sessionCookie.startsWith("q_session_kc-mcp-ui-demo="), alice.sessionCookie);
        String id = alice.id();
        assertFalse(id.contains("."), "the cookie carries an opaque id, not a token: " + id);

        alice.get("/bff/me")
            .then()
            .statusCode(200)
            .body("authenticated", equalTo(true))
            .body("idp", equalTo("demo"))
            .body("username", equalTo("alice"))
            .body("email", equalTo("alice@example.com"))
            .body("realm", equalTo("demo"))
            .body("roles", hasItem("realm-management.realm-admin"))
            .body("admin", equalTo(true))
            .body("adminRole", equalTo("realm-management.realm-admin"));
        alice.get("/bff/api/systems").then().statusCode(200).body("systems.alias", hasItem("default"));

        // the row: plain tokens through the store, encrypted in the table; issuer,
        // subject
        // and sid recorded
        UserSession stored = sessions.store().find(id).orElseThrow();
        assertEquals("demo", stored.idp());
        assertEquals(UiTestResource.base + "/realms/demo", stored.issuer());
        assertNotNull(stored.subject());
        assertNotNull(stored.sid());
        assertTrue(stored.idToken().startsWith("eyJ"), "ID token readable through the store");
        assertNotNull(stored.refreshToken());
        UserSessionEntity row = QuarkusTransaction.requiringNew().call(() -> UserSessionEntity.findById(id));
        assertTrue(row.idToken.startsWith("enc:v2:"), "encrypted in the database: " + row.idToken.substring(0, 12));
        assertTrue(row.refreshToken.startsWith("enc:v2:"));
        assertEquals(stored.subject(), row.subject);
        assertEquals(stored.sid(), row.sid);

        // logout: RP-initiated at Keycloak, back to the page with the provider named, the
        // row
        // is gone, the cookie useless
        Response logout = alice.get("/bff/logout");
        assertEquals(302, logout.statusCode());
        assertTrue(logout.header("Location").contains("/protocol/openid-connect/logout"), logout.header("Location"));
        assertTrue(logout.header("Location").contains("id_token_hint="), logout.header("Location"));
        String returnTo = Browser.query(logout.header("Location")).get("post_logout_redirect_uri");
        assertNotNull(returnTo, logout.header("Location"));
        assertTrue(returnTo.startsWith("http://localhost:" + RestAssured.port + "/ui/?idp=demo"), returnTo);
        assertFalse(returnTo.contains("?state"), "one query only: " + returnTo);
        assertTrue(sessions.store().find(id).isEmpty(), "session row deleted on logout");
        assertStaleCookieIsUseless(alice);
    }

    @Test
    void viewerSignsInButLacksTheManagementRole() {
        Browser carol = Browser.login("second", "carol", "carol");
        assertTrue(carol.sessionCookie.startsWith("q_session_kc-mcp-ui-second="), carol.sessionCookie);
        carol.get("/bff/me")
            .then()
            .statusCode(200)
            .body("authenticated", equalTo(true))
            .body("idp", equalTo("second"))
            .body("username", equalTo("carol"))
            .body("admin", equalTo(false));
        carol.get("/bff/api/systems").then().statusCode(403).body("error", equalTo("forbidden"));
    }

    @Test
    void backChannelLogoutEndsTheSessionAtOnce() throws InterruptedException {
        Browser alice = Browser.login("demo", "alice", "alice");
        String id = alice.id();
        assertNotNull(sessions.store().find(id).orElseThrow().sid(), "the provider's session id is recorded");

        // a token nobody signed is refused
        given().contentType("application/x-www-form-urlencoded")
            .formParam("logout_token", "eyJhbGciOiJub25lIn0.eyJpc3MiOiJ4IiwiYXVkIjoieSJ9.")
            .post("/bff/backchannel-logout")
            .then()
            .statusCode(400)
            .body("error", equalTo("invalid_request"));

        // Keycloak ends alice's SSO session and posts the logout token to the server
        String userId = UiTestResource.enableBackChannelLogout("keycloak-mcp-ui", RestAssured.port, "alice");
        UiTestResource.logoutUser(userId);
        long deadline = System.currentTimeMillis() + 15_000;
        while (sessions.store().find(id).isPresent() && System.currentTimeMillis() < deadline) {
            Thread.sleep(200);
        }
        assertTrue(sessions.store().find(id).isEmpty(), "the session row is gone after the back-channel logout");
        assertStaleCookieIsUseless(alice);
    }

    @Test
    void sessionCheckRenewsTheSessionAndNoticesALogoutElsewhere() {
        // carol's provider "second" has no back-channel logout URL: only the check can
        // tell
        Browser carol = Browser.login("second", "carol", "carol");
        String id = carol.id();
        UserSession before = sessions.store().find(id).orElseThrow();
        Response ok = carol.post("/bff/check-session");
        assertEquals(200, ok.statusCode(), ok.asString());
        assertTrue(ok.jsonPath().getBoolean("active"));
        assertNotNull(ok.jsonPath().getString("sessionExpiresAt"));
        assertTrue(
                ok.headers()
                    .getValues("Set-Cookie")
                    .stream()
                    .anyMatch(c -> c.startsWith("q_session_kc-mcp-ui-second=" + id + ";") && c.contains("Max-Age=")),
                "cookie re-sent: " + ok.headers().getValues("Set-Cookie"));
        UserSession after = sessions.store().find(id).orElseThrow();
        assertEquals(id, after.id());
        assertFalse(before.refreshToken().equals(after.refreshToken()) && before.idToken().equals(after.idToken()),
                "tokens renewed");
        assertEquals(before.sid(), after.sid());
        // the check without the header is refused like every write
        given().header("Cookie", carol.sessionCookie)
            .post("/bff/check-session")
            .then()
            .statusCode(403)
            .body("error", equalTo("missing_request_header"));

        // Keycloak ends carol's SSO session: the next check says so and deletes the row
        UiTestResource.logoutUser(UiTestResource.userId("carol"));
        Response ended = carol.post("/bff/check-session");
        assertEquals(401, ended.statusCode(), ended.asString());
        assertEquals("session_ended", ended.jsonPath().getString("error"));
        assertTrue(sessions.store().find(id).isEmpty(), "row deleted after the failed check");
        assertStaleCookieIsUseless(carol);
    }

    @Test
    void writesNeedTheJavaScriptHeader() {
        Browser alice = Browser.login("demo", "alice", "alice");
        given().header("Cookie", alice.sessionCookie)
            .contentType("application/json")
            .body("{}")
            .post("/bff/api/systems")
            .then()
            .statusCode(403)
            .body("error", equalTo("missing_request_header"));
    }

    /**
     * A cookie whose row is gone: the UI's request gets 499 (no redirect) and the cookie
     * is cleared, a plain request 401; without the cookie the browser is anonymous again.
     */
    private static void assertStaleCookieIsUseless(Browser browser) {
        Response afterwards = browser.get("/bff/me");
        assertTrue(afterwards.statusCode() == 499 || afterwards.statusCode() == 401,
                "stale cookie: " + afterwards.statusCode() + " " + afterwards.asString());
        String cookieName = browser.sessionCookie.substring(0, browser.sessionCookie.indexOf('='));
        assertTrue(
                afterwards.headers()
                    .getValues("Set-Cookie")
                    .stream()
                    .anyMatch(c -> c.startsWith(cookieName + "=") && c.contains("Max-Age=0")),
                "cookie cleared: " + afterwards.headers().getValues("Set-Cookie"));
        given().get("/bff/me").then().statusCode(200).body("authenticated", equalTo(false));
    }

    /**
     * A browser with one session cookie, cookies handled by hand (the cookie is Secure,
     * the test port http).
     */
    record Browser(String sessionCookie) {

        String id() {
            return sessionCookie.substring(sessionCookie.indexOf('=') + 1);
        }

        Response get(String path) {
            return given().header("Cookie", sessionCookie)
                .header(UiTenant.JAVASCRIPT_HEADER, UiTenant.JAVASCRIPT_HEADER_VALUE)
                .redirects()
                .follow(false)
                .get(path);
        }

        Response post(String path) {
            return given().header("Cookie", sessionCookie)
                .header(UiTenant.JAVASCRIPT_HEADER, UiTenant.JAVASCRIPT_HEADER_VALUE)
                .redirects()
                .follow(false)
                .post(path);
        }

        /** Runs the code flow at Keycloak the way a browser does. */
        static Browser login(String idp, String user, String password) {
            try {
                // 1. the sign-in button: Quarkus starts the flow with PKCE
                Response start = given().redirects().follow(false).get("/bff/login?idp=" + idp);
                assertEquals(302, start.statusCode(), start.asString());
                String authorize = start.header("Location");
                assertTrue(authorize.contains("code_challenge_method=S256"), authorize);
                assertTrue(authorize.contains("response_type=code"), authorize);
                Map<String, String> params = query(authorize);
                assertEquals("http://localhost:" + RestAssured.port + "/bff/login", params.get("redirect_uri"));
                List<String> stateCookies = new ArrayList<>();
                for (String c : start.headers().getValues("Set-Cookie")) {
                    if (c.startsWith("q_auth_kc-mcp-ui-" + idp)) {
                        stateCookies.add(c.substring(0, c.indexOf(';')));
                    }
                }
                assertEquals(1, stateCookies.size(), "one state cookie: " + start.headers().getValues("Set-Cookie"));

                // 2. Keycloak's login page, the form posted
                HttpResponse<String> page = HTTP.send(HttpRequest.newBuilder(URI.create(authorize)).GET().build(),
                        HttpResponse.BodyHandlers.ofString());
                assertEquals(200, page.statusCode(), page.body());
                Matcher m = FORM_ACTION.matcher(page.body());
                assertTrue(m.find(), "login form");
                String action = m.group(1).replace("&amp;", "&");
                String kcCookies = String.join("; ",
                        page.headers()
                            .allValues("Set-Cookie")
                            .stream()
                            .map(c -> c.substring(0, c.indexOf(';')))
                            .toList());
                HttpResponse<String> submitted = HTTP.send(HttpRequest.newBuilder(URI.create(action))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .header("Cookie", kcCookies)
                    .POST(HttpRequest.BodyPublishers
                        .ofString("username=" + user + "&password=" + password + "&credentialId="))
                    .build(), HttpResponse.BodyHandlers.ofString());
                assertEquals(302, submitted.statusCode(), submitted.body());
                String callback = submitted.headers().firstValue("Location").orElseThrow();
                assertTrue(callback.startsWith(params.get("redirect_uri") + "?"), callback);
                assertTrue(callback.contains("code="), callback);

                // 3. back at the server: code exchanged, session cookie set, on to the UI
                Response exchanged = given().header("Cookie", String.join("; ", stateCookies))
                    .redirects()
                    .follow(false)
                    .get(callback.substring(callback.indexOf("/bff/login")));
                assertEquals(302, exchanged.statusCode(), exchanged.asString());
                assertEquals(params.get("redirect_uri"), exchanged.header("Location"));
                String session = null;
                for (String c : exchanged.headers().getValues("Set-Cookie")) {
                    if (c.startsWith("q_session_kc-mcp-ui-" + idp + "=")) {
                        assertTrue(c.toLowerCase().contains("httponly"), c);
                        assertTrue(c.contains("Secure"), c);
                        session = c.substring(0, c.indexOf(';'));
                    }
                }
                assertNotNull(session, "session cookie: " + exchanged.headers().getValues("Set-Cookie"));
                assertFalse(exchanged.headers().getValues("Set-Cookie").stream().anyMatch(c -> c.startsWith("kc_mcp")),
                        "no cookie beyond the session: " + exchanged.headers().getValues("Set-Cookie"));
                Browser browser = new Browser(session);
                Response login = browser.get("/bff/login");
                assertEquals(303, login.statusCode(), login.asString());
                assertTrue(login.header("Location").endsWith("/ui/"), login.header("Location"));
                return browser;
            }
            catch (IOException | InterruptedException e) {
                throw new IllegalStateException(e);
            }
        }

        static Map<String, String> query(String url) {
            Map<String, String> out = new LinkedHashMap<>();
            for (String pair : url.substring(url.indexOf('?') + 1).split("&")) {
                int eq = pair.indexOf('=');
                out.put(URLDecoder.decode(pair.substring(0, eq), StandardCharsets.UTF_8),
                        URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8));
            }
            return out;
        }
    }
}
