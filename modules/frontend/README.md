# keycloak-mcp-server-frontend

The management UI: a [Lit](https://lit.dev) single-page app in `src/main/webui`, built with Vite, packaged by Maven as
static resources (`META-INF/resources/ui`) and served by the backend at `/ui/`. The backend-for-frontend it talks to
(`/bff`) is in `modules/backend`, package `backend.ui`; the browser never sees a token.

## What is here

| file | purpose |
|---|---|
| `src/main/webui/src/bff.ts` | the BFF client: `me()`, `systems()`, `login(idp)`, `logout(me)`; every fetch carries `X-Requested-With: JavaScript` |
| `src/main/webui/src/kc-mcp-app.ts` | `<kc-mcp-app>`: who is signed in, one sign-in button per identity provider, sign-out, the API test; `trackActivity()` runs `checkSession()` whenever the tab becomes visible (Page Visibility API) and resets the page when the session ended elsewhere |
| `src/main/webui/vite.config.ts` | `base: /ui/`; `npm run dev` serves https://localhost:5173 and proxies `/bff` to the server |
| `pom.xml` | `frontend-maven-plugin`: downloads Node (`frontend.node.version`, into `node/`), `npm ci`, `npm run build` |

## The BFF contract

| call | answer |
|---|---|
| `GET /bff/me[?idp=<alias>]` | `{authenticated, idps: [{alias, displayName, loginPath}], logoutPath, suggestedIdp?}`: the providers of the login page (hidden ones never), `idp` (the return from a logout) marks one of them as `suggestedIdp`; signed in also `idp, subject, username, name, email, realm, issuer, roles, adminRole, admin, sessionExpiresAt` |
| `GET /bff/login?idp=<alias>` | full-page navigation: code flow with PKCE at that provider, then `/ui/`; `idp` optional with one provider |
| `GET /bff/logout` | full-page navigation: RP-initiated logout, session row deleted, back to `/ui/` |
| `GET /bff/api/systems` | the systems, as `GET /admin/systems`; needs `kc-mcp.admin.role` on the access token |
| `POST /bff/check-session` | `{active: true, checkedAt, sessionExpiresAt, cookieExpiresAt, accessTokenExpiresAt}` and a renewed cookie; 401 `{active: false, error: "session_ended"}` once the session ended at the provider (the client resolves `false`); 503 `idp_unavailable` |
| `POST /bff/backchannel-logout` | for the identity provider, not the browser: its logout token ends the matching sessions |
| any `/bff/api/*` | 499 when the session is gone (no redirect, because of the header); writes need the header (403 `missing_request_header` otherwise); 403 `forbidden` without the role |

Errors are `{"error": "<code>", "message": "..."}` like the admin API. New pages add methods to `UiResource` and call
the admin services (`AdminSystems`, `AdminSecrets`, `AdminStorage`) directly; `UiAccessFilter` already checks the
session, the role and the header.

## Working on it

```shell
etc/mkcert.sh                                            # once: .certs/localhost*.pem (the cookie is Secure)
cd examples/run-modes && docker compose up -d && cd ../..  # Keycloak :8080 with the demo realm and the client keycloak-mcp-ui
set -a; source examples/management-ui/env/ui.env; set +a
./mvnw quarkus:dev -pl modules/backend -am               # https://localhost:8443/ui/  (alice / alice-demo)
```

Live reload of the UI: in a second terminal

```shell
cd modules/frontend/src/main/webui
npm install && npm run dev                               # https://localhost:5173/ui/, /bff proxied to :8443
```

Both ports are registered as redirect URIs of `keycloak-mcp-ui` in the demo realm. `npm run build` writes `dist/`,
the Maven build writes `target/classes/META-INF/resources/ui` (emptied first) and packs it; `./mvnw package -Dui.skip=true` skips Node and npm (the jar then has
no UI, `/ui/` answers 404 and the server says so at startup). IntelliJ: `.run/dev-ui`, `.run/management-ui-vite`.

TypeScript uses Lit's classic decorators (`experimentalDecorators`, `useDefineForClassFields: false`).
