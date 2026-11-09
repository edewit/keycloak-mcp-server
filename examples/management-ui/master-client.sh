#!/usr/bin/env bash
# Creates the public PKCE client keycloak-mcp-ui in the master realm of the run-modes Keycloak (:8080, admin/admin),
# for env/ui-two-idps.env. Idempotent.
set -euo pipefail
KC=${KC:-http://localhost:8080}
TOKEN=$(curl -sf "$KC/realms/master/protocol/openid-connect/token" \
  -d 'grant_type=password&client_id=admin-cli&username=admin&password=admin' | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')
if curl -sf -H "Authorization: Bearer $TOKEN" "$KC/admin/realms/master/clients?clientId=keycloak-mcp-ui" | grep -q '"clientId"'; then
  echo "master/keycloak-mcp-ui exists"; exit 0
fi
curl -sf -X POST "$KC/admin/realms/master/clients" -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d '{
  "clientId": "keycloak-mcp-ui", "name": "Keycloak MCP server UI", "publicClient": true, "standardFlowEnabled": true,
  "directAccessGrantsEnabled": false, "fullScopeAllowed": true,
  "redirectUris": ["https://localhost:8443/bff/login"],
  "webOrigins": ["+"],
  "attributes": {"pkce.code.challenge.method": "S256", "post.logout.redirect.uris": "https://localhost:8443/ui/*",
                 "backchannel.logout.url": "http://host.docker.internal:8081/bff/backchannel-logout", "backchannel.logout.session.required": "true"}
}'
echo "created master/keycloak-mcp-ui"
