#!/usr/bin/env bash
# The client scopes for clients Keycloak creates from a metadata document. Such a client gets the realm's default
# scopes, so all three become realm-level optional scopes. Not in the realm file: a clientScopes array in an import
# replaces Keycloak's built-in scopes. Safe to run again.
set -euo pipefail
cd "$(dirname "$0")"

kc() { docker compose exec -T keycloak /opt/keycloak/bin/kcadm.sh "$@"; }
kc config credentials --server http://localhost:8080 --realm master --user admin --password admin </dev/null >/dev/null

scope_id() { kc get client-scopes -r demo --fields id,name --format csv --noquotes </dev/null | awk -F, -v n="$1" '$2==n {print $1}'; }

# mcp-server: the audience the MCP server demands
if [ -z "$(scope_id mcp-server)" ]; then
  kc create client-scopes -r demo -f - >/dev/null <<'JSON'
{
  "name": "mcp-server",
  "description": "Access to the MCP server",
  "protocol": "openid-connect",
  "attributes": { "display.on.consent.screen": "true", "consent.screen.text": "Use the Keycloak MCP server" },
  "protocolMappers": [{
    "name": "mcp server audience",
    "protocol": "openid-connect",
    "protocolMapper": "oidc-audience-mapper",
    "config": {
      "included.custom.audience": "keycloak-mcp-server",
      "access.token.claim": "true",
      "id.token.claim": "false",
      "introspection.token.claim": "true"
    }
  }]
}
JSON
  echo "created client scope mcp-server"
fi

# mcp-admin-roles: a client created from a metadata document has fullScopeAllowed=false, so without a scope mapping
# the token carries no roles and the Admin API answers 403. Separate from mcp-server because Keycloak drops a scope
# with role mappings for users holding none of its roles, and those users should still reach the server.
if [ -z "$(scope_id mcp-admin-roles)" ]; then
  kc create client-scopes -r demo -f - >/dev/null <<'JSON'
{
  "name": "mcp-admin-roles",
  "description": "The user's realm administration roles",
  "protocol": "openid-connect",
  "attributes": { "display.on.consent.screen": "true", "consent.screen.text": "Administer this realm with your roles" }
}
JSON
  echo "created client scope mcp-admin-roles"
fi
management_id=$(kc get clients -r demo -q clientId=realm-management --fields id --format csv --noquotes </dev/null)
roles=$(kc get "clients/$management_id/roles" -r demo --fields id,name </dev/null)
roles_scope_id=$(scope_id mcp-admin-roles)
printf '%s' "$roles" | kc create "client-scopes/$roles_scope_id/scope-mappings/clients/$management_id" -r demo -f - >/dev/null
echo "mcp-admin-roles maps the realm-management roles"

optional=$(kc get realms/demo/default-optional-client-scopes -r demo --fields name --format csv --noquotes </dev/null)
for name in kc-admin-api mcp-server mcp-admin-roles; do
  if ! grep -qx "$name" <<<"$optional"; then
    kc update "realms/demo/default-optional-client-scopes/$(scope_id "$name")" </dev/null >/dev/null
  fi
  echo "$name is a realm optional scope"
done
