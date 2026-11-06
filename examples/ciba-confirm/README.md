# CIBA confirmation: destructive tools approved on the user's own device

`confirm: true` is written by the model and elicitation is answered by the MCP client, so neither proves that a human
agreed to a destructive operation. This example confirms destructive tools through OpenID Connect
**Client Initiated Backchannel Authentication (CIBA)**: before the tool runs, the MCP server files an authentication
request for the signed-in user with the OpenID provider, the provider delivers it to the user's device with a
*binding message* that names the operation, and the tool runs once the user approves there. The model never touches
that channel.

```
MCP client ──(OAuth 2.1 / PKCE)──▶ Keycloak            alice logs in, her token reaches the MCP server
   │ tools/call keycloak_user_delete {id, username}                                   (first call)
   ▼
MCP server (Confirmer chain: ciba-confirmer)
   │ 1. POST backchannel_authentication_endpoint        client mcp-ciba, login_hint=alice,
   │                                                     binding_message=kc-mcp-<hash of tool+realm+args>,
   │                                                     code=42, requester=<MCP client>, operation=Delete user (realm demo)
   │ 2. answers confirmation_required at once           "approve on your device, the device asks for the number 42"
   │ 3. Keycloak → authentication channel → the device  here: the "approver" at http://localhost:8095/, which shows
   │                                                     who asks for what and asks the user for the number
   │ tools/call keycloak_user_delete {id, username}                                   (second call)
   │ 4. poll token endpoint (grant urn:openid:params:grant-type:ciba): approved / declined / still pending / expired
   ▼
Admin REST API with alice's token (forward delegation)  → the user is deleted; declined → cancelled; pending → call again
```

The number works like Entra ID's number matching: it is shown where the request originates (the chat) and asked
for where it is approved (the device). A push the user did not trigger carries a number they cannot know, so
approval fatigue does not help an attacker who holds a session. The device also sees the requester (the MCP
client's name) and the operation, both sent as additional CIBA request parameters that Keycloak forwards.

The confirmer only uses the standard CIBA flow (discovery, `backchannel_authentication_endpoint`, `login_hint`,
`binding_message`, poll mode), so it works with any CIBA-capable provider. What differs per provider is the
*authentication device*: a bank's app, a push notification, a hardware token. Keycloak ships an HTTP authentication
channel that POSTs each request to a URL of your choice; the `approver` service of this example is that URL, a small
web app standing in for the device. It is an OpenID Connect relying party of the same realm (public client
`ciba-approver`, authorization code flow with PKCE): a user signs in, sees only the requests meant for them
(`login_hint` = their username or email), approves with the number from the chat or declines, and signs out again
(RP-initiated logout). The MCP server itself stays what CIBA calls the consumption device; it has no user-facing
part in this flow.

## Start

```shell
cd examples/ciba-confirm
docker compose up -d        # Keycloak 26.8.2 on http://localhost:8098 (admin / admin), the approver on http://localhost:8095
```

Then run the MCP server on the host:

```shell
cd ../..
set -a; source examples/ciba-confirm/env/ciba.env; set +a
./mvnw quarkus:dev -pl modules/backend -am     # MCP endpoint: http://localhost:8099/mcp
```

Use a fresh shell, or one that has not sourced another example's env file: variables the other file sets and this
one does not (such as `QUARKUS_OIDC_RESOURCE_METADATA_SCOPES` from `delegated-auth`) would carry over and make the
login ask for scopes this realm does not have.

Or let compose run it from the packaged jar (`./mvnw package -DskipTests` first):

```shell
docker compose --profile mcp up -d --build
```

## Run

```shell
./demo.sh
```

The script logs in as `alice` (realm admin), creates a throw-away user and asks to delete it. The first call files
the CIBA request and answers `confirmation_required` with the number. On alice's device, where the script holds her
access token the way the browser holds her session, the request shows who asks for what and asks for the number: a
wrong one is refused, the right one approves. The second call collects the approval and deletes the user. The next
round declines: the second call answers `cancelled` and the user stays. Then `carol`, signed in to the device as
herself, sees none of alice's requests and cannot decide them. The last round passes `confirm: true`, which changes
nothing: a request reaches the device all the same.

In the browser: open <http://localhost:8095/>, sign in as `alice / alice-demo`, then ask LM Studio (or
`./mcp-call.py --login alice:alice-demo keycloak_user_delete '{...}'`) to delete a user; the request appears on the
page, enter the number the chat shows and approve. "Sign out" ends the session here and at Keycloak.

With LM Studio or another OAuth-capable MCP client: add `mcp-oauth.json`, log in as `alice / alice-demo`, ask it to
delete a user, then approve or decline on the device page, signed in as alice. The model's answer names the binding
message and the number the page asks for, so you can tell which request belongs to which operation.

## What to look at

- `env/ciba.env`: `KC_MCP_SPI_CIBA_CONFIRMER_*` (client, timeout, `when`, `login-hint`, `client-auth`, `flow`,
  `number-matching`) and `KC_MCP_CONFIRM_FALLBACK=deny`, so a client without elicitation cannot fall back to
  `confirm: true`.
- `realms/demo-realm.json`: the realm's CIBA policy (`cibaInterval`, `cibaExpiresIn`, `login_hint` as the user
  hint), the confidential client `mcp-ciba` with `oidc.ciba.grant.enabled`, the public client `mcp-consumer` whose
  tokens carry `aud=mcp-admin`, and the public client `ciba-approver` the device signs its users in with.
- `docker-compose.yml`: Keycloak's `--spi-ciba-auth-channel--ciba-http-auth-channel--http-authentication-channel-uri`
  pointing at the approver.
- `approver/Approver.java`: plain JDK, no build. The contract with Keycloak is a `201` to the request and a
  `POST {"status": "SUCCEED" | "CANCELLED"}` with Keycloak's bearer token to
  `/realms/demo/protocol/openid-connect/ext/ciba/auth/callback`. It reads `code`, `requester` and `operation` from
  the request (Keycloak forwards additional CIBA request parameters as top-level JSON fields), shows a request only
  to the signed-in user it names, refuses an approval whose number does not match, and takes the user's identity
  from the `userinfo` endpoint after the code exchange (browser) or for a bearer token (scripts: `GET /pending`,
  `POST /approve/{id|latest}?code=NN`, `POST /decline/{id|latest}`, `POST /decline-all`, `POST /history/clear`).
  Requests are numbered; the page lists them newest first with "Decline all" above several pending ones and
  "Clear" above the user's decided list.
- The server log: `CIBA request …<id> for alice: keycloak_user_delete realm demo (binding message kc-mcp-…, code 42,
  up to 90 s)`, then `approved by alice` or `declined by alice`; the audit line of the tool call follows.

## Beyond the demo

- Other providers: point `KC_MCP_SPI_CIBA_CONFIRMER_ISSUER` at the provider (or leave `caller` to follow the issuer
  of the caller's token), register a confidential CIBA client there, pick `client-auth=client_secret_post` if it does
  not take HTTP Basic, and set `login-hint` to the claim the provider resolves users by (`email`, `sub`, ...).
  `requested-expiry=true` asks the provider to keep the request as long as the server waits; `binding-message=false`
  drops the message for providers that reject it.
- `KC_MCP_SPI_CIBA_CONFIRMER_WHEN=without-elicitation` keeps CIBA for clients that cannot ask the human and lets
  clients with elicitation (Claude Desktop, ...) ask in the chat instead.
- `KC_MCP_SPI_CIBA_CONFIRMER_FLOW=blocking` makes the tool call wait for the device instead of answering twice;
  simpler for scripts, but the chat shows nothing while waiting, so there is no number to match
  (`number-matching` only applies to the two-step flow). Devices that cannot show additional parameters still get
  the binding message; `extra-parameters=false` stops sending them.
- Only DESTRUCTIVE tools are confirmed; `keycloak_realm_update` and `keycloak_auth_flow_bind` count as such. Other
  `Confirmer`s (a change ticket check, see `examples/extensions`) run before this one and may confirm or decline first.
