#!/bin/bash
# What a SaaS onboarding job does per tenant: a confidential client for the MCP server in the tenant's master
# realm, authenticating with a Signed JWT whose public key Keycloak fetches from the MCP server, and the
# admin roles of every realm the tenant owns on the client's service account. Idempotent.
set -euo pipefail
KC=/opt/keycloak/bin/kcadm.sh
$KC config credentials --server http://keycloak:8080 --realm master --user admin --password admin

onboard() {
  local tenant=$1; shift
  local client="keycloak-mcp-server-$tenant"
  local id
  id=$($KC get clients -r master -q clientId="$client" --fields id --format csv --noquotes | head -1 || true)
  if [ -z "$id" ]; then
    id=$(printf '{"clientId":"%s","name":"MCP server for %s","enabled":true,"protocol":"openid-connect","publicClient":false,"serviceAccountsEnabled":true,"standardFlowEnabled":false,"directAccessGrantsEnabled":false,"fullScopeAllowed":false,"clientAuthenticatorType":"client-jwt","attributes":{"use.jwks.url":"true","jwks.url":"http://mcp:8081/auth/keys/%s/jwks.json","token.endpoint.auth.signing.alg":"RS256"}}' \
        "$client" "$tenant" "$tenant" | $KC create clients -r master -i -f -)
    echo "created client $client ($id) with JWKS URL http://mcp:8081/auth/keys/$tenant/jwks.json"
  else
    echo "client $client exists ($id)"
  fi
  # master has one client per realm (<realm>-realm) carrying that realm's admin roles; no realm-admin composite there
  local roles=(manage-realm manage-users manage-clients manage-events manage-identity-providers manage-authorization
               create-client impersonation view-realm view-users view-clients view-events view-identity-providers
               view-authorization query-realms query-users query-clients query-groups)
  for realm in "$@"; do
    # the service account holds the roles ...
    $KC add-roles -r master --uusername "service-account-$client" --cclientid "${realm}-realm" \
      $(printf -- '--rolename %s ' "${roles[@]}")
    # ... and the client's role scope lets them into its tokens (full scope allowed is off, as Keycloak asks)
    local realm_client
    realm_client=$($KC get clients -r master -q clientId="${realm}-realm" --fields id --format csv --noquotes | head -1)
    $KC get "clients/$realm_client/roles" -r master --fields id,name \
      | $KC create "clients/$id/scope-mappings/clients/$realm_client" -r master -f - >/dev/null
    echo "  $client administers $realm"
  done
}

onboard tenant-a realm-a-1 realm-a-2
onboard tenant-b realm-b-1
echo "tenants onboarded"
