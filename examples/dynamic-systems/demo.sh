#!/usr/bin/env bash
# The whole flow, step by step. Needs the stack up (docker compose up -d --build), curl, jq and python3.
#
#   1. register the system "acme" in the MCP server (admin API -> PostgreSQL, key pair generated in the database vault)
#   2. create the keycloak-mcp-server client in Keycloak's master realm, JWKS URL = what the API answered
#   3. create the realm acme-dev with the public mcp-consumer client and the demo users
#   4. call tools: as the service account (port 8091) and as the realm's users (port 8092)
#   5. a second system "acme-cs" that authenticates with a client secret kept in the MCP server's vault
set -euo pipefail
cd "$(dirname "$0")"
MCP=http://localhost:8091
MCP_INTERNAL=http://mcp:8081                       # how Keycloak reaches the MCP server inside the compose network
ADMIN_TOKEN=${KC_MCP_ADMIN_TOKEN:-demo-admin-token}
KCADM="docker compose exec -T keycloak /opt/keycloak/bin/kcadm.sh"

step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
# master's admin role for a client's service account: it administers every realm of this Keycloak; the client's
# role scope lets the role into its tokens (full scope allowed is off, as Keycloak asks)
grant_master_admin() {
  $KCADM add-roles -r master --uusername "service-account-$1" --rolename admin
  $KCADM get roles/admin -r master --fields id,name | sed 's/^{/[{/; s/}$/}]/' \
    | $KCADM create "clients/$2/scope-mappings/realm" -r master -f - >/dev/null
  echo "service account of $1 holds master/admin, in the client's role scope"
}
admin() {
  curl -sS \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H 'Content-Type: application/json' \
    "$@"
}

step "1. register the system 'acme' (stored in PostgreSQL, key pair generated in the database vault)"
SYSTEM=$(admin -X PUT "$MCP/admin/systems/acme" -d @- <<'JSON'
{
  "displayName": "ACME Corp.",
  "url": "http://keycloak:8080",
  "issuer": "http://localhost:8090/realms/master",
  "authRealm": "master",
  "clientId": "keycloak-mcp-server",
  "clientAuth": "private_key_jwt",
  "defaultRealm": "acme-dev",
  "allowedRealms": ["acme-dev"],
  "version": "26.8.2",
  "signingKey": "generate"
}
JSON
)
echo "$SYSTEM" | jq .
if echo "$SYSTEM" | jq -e '.error == "signing_key_exists"' >/dev/null; then
  echo "(already registered with a key; replacing the settings, keeping the key)"
  SYSTEM=$(admin -X PUT "$MCP/admin/systems/acme" -d "$(echo '{}' | jq '. + {"displayName":"ACME Corp.","url":"http://keycloak:8080","issuer":"http://localhost:8090/realms/master","defaultRealm":"acme-dev","allowedRealms":["acme-dev"],"version":"26.8.2","signingKey":"existing"}')")
fi
JWKS_PATH=$(echo "$SYSTEM" | jq -r .signingKey.jwksPath)
JWKS_URL="$MCP_INTERNAL$JWKS_PATH"
echo "JWKS for Keycloak: $JWKS_URL  (from the host: $MCP$JWKS_PATH)"
curl -s "$MCP$JWKS_PATH" | jq -c '.keys[0] | {kty, alg, kid}'

step "2. the keycloak-mcp-server client in the master realm, Signed JWT with that JWKS URL"
$KCADM config credentials --server http://localhost:8080 --realm master --user admin --password admin >/dev/null
CLIENT_ID=$($KCADM get clients -r master -q clientId=keycloak-mcp-server --fields id --format csv --noquotes | head -1 || true)
if [ -z "$CLIENT_ID" ]; then
  sed "s#\${MCP_JWKS_URL}#$JWKS_URL#" clients/keycloak-mcp-server.json | $KCADM create clients -r master -f - >/dev/null
  CLIENT_ID=$($KCADM get clients -r master -q clientId=keycloak-mcp-server --fields id --format csv --noquotes | head -1)
  echo "created client keycloak-mcp-server ($CLIENT_ID)"
else
  echo "client keycloak-mcp-server exists ($CLIENT_ID)"
fi
grant_master_admin keycloak-mcp-server "$CLIENT_ID"

step "2b. the public client keycloak-mcp-admin: people call the admin API with their own access token"
ADMIN_CLIENT_ID=$($KCADM get clients -r master -q clientId=keycloak-mcp-admin --fields id --format csv --noquotes | head -1 || true)
if [ -z "$ADMIN_CLIENT_ID" ]; then
  $KCADM create clients -r master -f - < clients/keycloak-mcp-admin.json >/dev/null
  ADMIN_CLIENT_ID=$($KCADM get clients -r master -q clientId=keycloak-mcp-admin --fields id --format csv --noquotes | head -1)
  echo "created client keycloak-mcp-admin ($ADMIN_CLIENT_ID)"
else
  echo "client keycloak-mcp-admin exists ($ADMIN_CLIENT_ID)"
fi
$KCADM get roles/admin -r master --fields id,name | sed 's/^{/[{/; s/}$/}]/' \
  | $KCADM create "clients/$ADMIN_CLIENT_ID/scope-mappings/realm" -r master -f - >/dev/null
# admin-cli tokens are lightweight in Keycloak 26 (no roles, no audience): the admin API refuses them, this client's work
TOKEN_URL=http://localhost:8090/realms/master/protocol/openid-connect/token
ADMIN_AT=$(curl -s "$TOKEN_URL" \
  -d 'grant_type=password&client_id=keycloak-mcp-admin&username=admin&password=admin' | jq -r .access_token)
curl -sS "$MCP/admin/systems" \
  -H "Authorization: Bearer $ADMIN_AT" | jq -c '[.systems[] | {alias, source}]'
CLI_AT=$(curl -s "$TOKEN_URL" \
  -d 'grant_type=password&client_id=admin-cli&username=admin&password=admin' | jq -r .access_token)
curl -s "$MCP/admin/systems" \
  -H "Authorization: Bearer $CLI_AT" \
  -o /dev/null -w 'the same with an admin-cli token (no audience, no roles): HTTP %{http_code}\n'

step "3. the realm acme-dev: public client mcp-consumer, groups with realm-management roles, users"
if $KCADM get realms/acme-dev >/dev/null 2>&1; then
  echo "realm acme-dev exists"
else
  $KCADM create realms -f - < realms/acme-dev.json
  echo "created realm acme-dev (alice = admin, sam = support, dave = developer, bob = disabled)"
fi

step "4a. as the service account (port 8091): the entry /mcp/s/acme/acme-dev"
./mcp-call.py "$MCP/mcp/s/acme/acme-dev" whoami | jq -c '{system, entry, keycloakCallsRunAs, server: .server.version}'
./mcp-call.py "$MCP/mcp/s/acme/acme-dev" keycloak_user_search '{"search": "alice"}' | jq -c '[.items[]?.username] // .'

step "4b. as the realm's users (port 8092): alice may do everything, sam reads, dave manages clients"
U=http://localhost:8092/mcp/s/acme/acme-dev
./mcp-call.py --login alice:alice-demo "$U" whoami | jq -c '{caller: .caller.username, keycloakCallsRunAs, roles: (.roles["acme-dev"] | length)}'
./mcp-call.py --login alice:alice-demo "$U" keycloak_user_set_enabled '{"id": "bob", "enabled": true}' | jq -c '{username, enabled} // .'
./mcp-call.py --login sam:sam-demo "$U" keycloak_user_search '{"search": "bob"}' | jq -c '[.items[]?.username] // .'
./mcp-call.py --login sam:sam-demo "$U" keycloak_user_set_enabled '{"id": "bob", "enabled": false}' | jq -c '{error, message}'
./mcp-call.py --login dave:dave-demo "$U" keycloak_client_list '{}' | jq -c '[.items[]?.clientId] // .'
./mcp-call.py --login dave:dave-demo "$U" keycloak_user_delete '{"id": "bob", "username": "bob"}' | jq -c '{error, message}'
./mcp-call.py --login alice:alice-demo "$U" keycloak_user_set_enabled '{"id": "bob", "enabled": false}' | jq -c '{username, enabled} // .'

step "5. a client_secret system: the secret lives in the vault, the system only carries vault:acme/client-secret"
CS_CLIENT_ID=$($KCADM get clients -r master -q clientId=keycloak-mcp-server-secret --fields id --format csv --noquotes | head -1 || true)
if [ -z "$CS_CLIENT_ID" ]; then
  CLIENT_SECRET=$(openssl rand -hex 24)
  sed "s#\${MCP_CLIENT_SECRET}#$CLIENT_SECRET#" clients/keycloak-mcp-server-secret.json | $KCADM create clients -r master -f - >/dev/null
  CS_CLIENT_ID=$($KCADM get clients -r master -q clientId=keycloak-mcp-server-secret --fields id --format csv --noquotes | head -1)
  echo "created client keycloak-mcp-server-secret ($CS_CLIENT_ID)"
  grant_master_admin keycloak-mcp-server-secret "$CS_CLIENT_ID"
else
  CLIENT_SECRET=$($KCADM get "clients/$CS_CLIENT_ID/client-secret" -r master --fields value --format csv --noquotes)
  echo "client keycloak-mcp-server-secret exists ($CS_CLIENT_ID)"
fi
# the secret goes into the vault once (PUT answers 201, a replacement 200); the API never returns it
admin -X PUT "$MCP/admin/secrets/acme/client-secret" -d "{\"value\": \"$CLIENT_SECRET\"}" | jq -c .
admin -X PUT "$MCP/admin/systems/acme-cs" -d @- <<'JSON' | jq -c '{alias, clientAuth, clientSecret, source, entries}'
{
  "displayName": "ACME Corp. (client secret)",
  "url": "http://keycloak:8080",
  "issuer": "http://localhost:8090/realms/master",
  "clientId": "keycloak-mcp-server-secret",
  "clientAuth": "client_secret",
  "clientSecret": "vault:acme/client-secret",
  "defaultRealm": "acme-dev",
  "allowedRealms": ["acme-dev"],
  "version": "26.8.2"
}
JSON
admin "$MCP/admin/secrets" | jq -c '{vault, writable, secrets: [.secrets[] | {name, usedBy}]}'
./mcp-call.py "$MCP/mcp/s/acme-cs/acme-dev" whoami | jq -c '{system, entry, keycloakCallsRunAs}'
./mcp-call.py "$MCP/mcp/s/acme-cs/acme-dev" keycloak_user_search '{"search": "dave"}' | jq -c '[.items[]?.username] // .'
admin -X DELETE "$MCP/admin/secrets/acme/client-secret" -w '\n(deleting a secret that a system uses: HTTP %{http_code})\n'

step "audit rows in PostgreSQL (the console of mcp-users shows pseudonyms, the rows the real names)"
docker compose exec -T postgres psql -U kcmcp -d kcmcp -c "select tool, outcome, caller_name, system_alias, realm from kc_mcp_audit_event order by id desc limit 8"
