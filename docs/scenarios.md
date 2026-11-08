# Scenarios in pictures

[keycloak-mcp-server](../README.md) › documentation

The ways the server is run, as diagrams: who talks to whom, which token carries each call, and where state lives.
Every scenario has a runnable example; the text next to each diagram names it and the page that explains the details.

## 1. One administrator, a service account

The local setup of the quick start's fallback (`examples/run-modes/env/realm-admin.env`): the server holds a
confidential client's credentials, every call runs with that service account, and its `realm-management` roles are the
ceiling. Nobody logs in; the MCP endpoint is anonymous and guarded against DNS rebinding instead.

```mermaid
flowchart LR
    M["MCP client<br/>(LM Studio, Claude Code, ...)"] -- "MCP over HTTP<br/>no login" --> S["keycloak-mcp-server<br/>profile local"]
    S -- "client_credentials<br/>client mcp-admin" --> K["Keycloak<br/>realm demo"]
    S -- "Admin REST API<br/>service account token" --> K
```

[Security](security.md) (profiles, access levels), [Configuration](configuration.md).

## 2. Users log in, their token is forwarded

The quick start and the shape a shared server has (`examples/run-modes/env/user-forward.env`, `KC_MCP_DELEGATION=forward`).
The MCP endpoint answers 401 with protected resource metadata, the client logs the user in at Keycloak with the
authorization code flow and PKCE, and the server passes the user's own token on to the Admin REST API. The server holds
no admin credentials; Keycloak enforces the user's roles on every call.

```mermaid
sequenceDiagram
    autonumber
    participant U as User
    participant C as MCP client
    participant S as keycloak-mcp-server
    participant K as Keycloak (realm demo)
    C->>S: POST /mcp initialize
    S-->>C: 401, WWW-Authenticate: Bearer resource_metadata=...
    C->>S: GET /.well-known/oauth-protected-resource
    S-->>C: authorization_servers: [realm demo], scopes
    C->>K: authorization code + PKCE (client mcp-consumer)
    K->>U: login page
    U-->>K: alice / alice-demo
    K-->>C: access token (aud mcp-admin, alice's roles)
    C->>S: POST /mcp ... Authorization: Bearer <alice>
    S->>S: verify token (OIDC tenant), access checks, confirmation
    S->>K: Admin REST API with alice's token
    K-->>S: result, enforced by alice's realm-management roles
    S-->>C: tool result, audited as caller=alice delegated
```

[Integrations](integrations.md) (the login's client side), [Security](security.md#callers).

## 3. The server as a delegated agent

`KC_MCP_DELEGATION=exchange` (`examples/delegated-auth/`): the user consents to the server's client acting for them, and
Keycloak's token exchange delegation issues a token that names both, `sub` the user and `act` the server's client. The
server's own role scope caps every delegated token, and Keycloak's events record who acted for whom.

```mermaid
sequenceDiagram
    autonumber
    participant C as MCP client
    participant S as keycloak-mcp-server<br/>(client keycloak-mcp)
    participant K as Keycloak
    C->>K: login with scope delegation:client:keycloak-mcp, user consents
    K-->>C: T_user (aud keycloak-mcp, may_act = keycloak-mcp)
    C->>S: POST /mcp ... Bearer T_user
    S->>S: verify T_user
    S->>K: client_credentials for keycloak-mcp
    K-->>S: T_sa (the actor's own token)
    S->>K: token exchange: subject_token=T_user, actor_token=T_sa
    K-->>S: T_del (sub = user, act = keycloak-mcp, roles = user's ∩ client's scope)
    S->>S: access checks and confirmation judged on T_del
    S->>K: Admin REST API with T_del
    K-->>S: result, TOKEN_EXCHANGE and admin events name user and actor
    S-->>C: tool result
```

[Security](security.md#callers), the example's README for the Keycloak setup (consent, Standard Token Exchange,
the `delegate` permission).

## 4. Several Keycloak systems, one entry per system or realm

Every Keycloak the server administers is a named system (`kc-mcp.systems.<name>.*`, a systems file, or the admin API).
A client at the root names the system in each call; a client bound to an entry does not and cannot reach another one.
Each entry logs its users in at its own realm: the server resolves an OIDC tenant per entry, so a token of Keycloak A
never reaches Keycloak B.

```mermaid
flowchart LR
    subgraph clients["MCP clients"]
        R["/mcp<br/>system named per call"]
        EP["/mcp/systems/prod<br/>bound to prod, login realm master"]
        ER["/mcp/systems/prod/customers<br/>bound to prod and realm customers,<br/>login realm customers"]
        ES["/mcp/systems/staging"]
    end
    S["keycloak-mcp-server<br/>one OIDC tenant per entry,<br/>caller issuer checked per system"]
    R --> S
    EP --> S
    ER --> S
    ES --> S
    S -- "key of prod (private_key_jwt)" --> A["Keycloak prod<br/>realms master, customers, ..."]
    S -- "key of staging" --> B["Keycloak staging"]
```

[Several Keycloak systems](systems.md), `examples/multi-tenant/`.

## 5. A shared server per environment

One deployment per environment behind a load balancer, several instances on one database: systems, keys, secrets,
pending approvals, UI logins and the audit trail are shared; MCP sessions of older clients stay on the instance that
opened them. The admin API can run on an instance of its own on the internal network, with the MCP endpoint switched
off there.

```mermaid
flowchart TB
    subgraph users["Administrators"]
        C1["MCP client"]
        C2["MCP client"]
    end
    LB["Load balancer<br/>affinity for clients that hold MCP sessions"]
    subgraph mcp["MCP-facing instances (profile shared)"]
        I1["instance 1<br/>kc-mcp.admin.enabled=false"]
        I2["instance 2<br/>kc-mcp.admin.enabled=false"]
    end
    ADM["admin instance (internal network)<br/>admin API, management UI,<br/>kc-mcp.mcp.enabled=false"]
    DB[("PostgreSQL<br/>systems, keys, secrets,<br/>approvals, sessions, audit")]
    K1["Keycloak A"]
    K2["Keycloak B"]
    OPS["Operator / automation<br/>issuer token or admin token"]
    C1 --> LB
    C2 --> LB
    LB --> I1
    LB --> I2
    I1 --> DB
    I2 --> DB
    ADM --> DB
    OPS --> ADM
    I1 --> K1
    I1 --> K2
    I2 --> K1
    I2 --> K2
    K1 -. "fetches JWKS per system" .-> LB
```

[Database storage](storage.md#several-instances-on-one-database), [Security](security.md) (profile `shared`).

## 6. Registering a system at runtime

With the database storage and the admin API on (`examples/dynamic-systems/`), a system is registered with one request.
The server creates the system's `private_key_jwt` key in its vault and publishes the public key per system; Keycloak's
client is configured with that JWKS URL, so no secret changes hands.

```mermaid
sequenceDiagram
    autonumber
    participant O as Operator
    participant S as keycloak-mcp-server
    participant DB as Database
    participant K as Keycloak acme
    O->>S: PUT /admin/systems/acme {url, authRealm, clientAuth: private_key_jwt, signingKey: generate}
    S->>DB: store system, create key pair (encrypted)
    S-->>O: 201 {signingKey.kid, jwksUrl: .../auth/keys/acme/jwks.json, entries}
    O->>K: client keycloak-mcp-server: Signed JWT, JWKS URL from the answer, service account roles
    Note over S,K: first call for system acme
    S->>K: token request signed with acme's key
    K->>S: GET /auth/keys/acme/jwks.json
    K-->>S: service account token
    Note over O,S: POST /admin/systems/acme/signing-key rotates the key, the JWKS keeps the retired one for a grace period
```

[Several Keycloak systems](systems.md#admin-api-registering-systems-at-runtime), the OpenAPI document at `/q/openapi`.

## 7. Approval on the user's device (CIBA)

The built-in `ciba-confirmer` (`examples/ciba-confirm/`) takes the decision on a destructive tool out of the channel the
model controls: the server files a backchannel authentication request for the signed-in user, the device shows what is
asked and a number, and the tool runs once the user approved there.

```mermaid
sequenceDiagram
    autonumber
    participant M as Model / MCP client
    participant S as keycloak-mcp-server
    participant K as Keycloak (CIBA)
    participant D as User's device
    M->>S: keycloak_user_delete dave
    S->>K: CIBA request: login_hint alice, binding_message, code 42, requester, operation
    K-->>S: auth_req_id
    S-->>M: confirmation_required {status requested, code 42, howTo}
    M->>M: shows "approve on your device, enter 42"
    K->>D: Delete user: dave (realm demo), requested by LM Studio
    D-->>K: alice enters 42, approves
    M->>S: keycloak_user_delete dave (same arguments)
    S->>K: poll token endpoint (auth_req_id)
    K-->>S: approved (ID token of alice)
    S->>K: Admin REST API: delete dave
    S-->>M: deleted, the audit records the approval
```

[CIBA confirmation](ciba-confirmation.md).

## 8. What every call goes through

Whatever the scenario, a tool call runs the same pipeline; a refusal at any step is a structured error that says what to
do next.

```mermaid
flowchart LR
    A["tool call"] --> B["entry binding<br/>system and realm pinned?"]
    B --> C["access policy<br/>roles, allow-lists,<br/>access checks (policies, self-protection)"]
    C --> D["arguments<br/>validation, coercion"]
    D --> E["realm check<br/>allowed realms, explicit target"]
    E --> F["confirmation<br/>elicitation, confirm flag,<br/>Confirmer, CIBA"]
    F --> G["handler<br/>Admin REST API with the<br/>identity of the scenario"]
    G --> H["audit<br/>caller, tool, outcome,<br/>secrets redacted"]
```

[Tools](tools.md), [Security](security.md), [Extending](extending.md) (your own checks and confirmers).
