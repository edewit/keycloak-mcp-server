#!/bin/bash
# Grants the Admin Permissions (fine-grained admin permissions V2) that let the client keycloak-mcp act on behalf of
# every user of the realm: a client policy naming keycloak-mcp as the allowed actor and a scope permission `delegate`
# on the Users resource type. Keycloak evaluates it when a login asks for the scope delegation:client:keycloak-mcp;
# without it the scope is silently dropped and the token carries no may_act claim. A realm import cannot carry these
# settings, so this job creates them once Keycloak is up (kcadm inside the Keycloak image). Idempotent.
set -euo pipefail
KC=/opt/keycloak/bin/kcadm.sh
REALM=${REALM:-demo}
ACTOR=${ACTOR:-keycloak-mcp}
$KC config credentials --server http://keycloak:8080 --realm master --user admin --password admin

perms=$($KC get clients -r "$REALM" -q clientId=admin-permissions --fields id --format csv --noquotes | head -1)
actor=$($KC get clients -r "$REALM" -q clientId="$ACTOR" --fields id --format csv --noquotes | head -1)
if [ -z "$perms" ] || [ -z "$actor" ]; then
  echo "realm $REALM needs Admin Permissions enabled (client admin-permissions) and the client $ACTOR" >&2
  exit 1
fi
authz="clients/$perms/authz/resource-server"

policy="$ACTOR may act for users"
if [ -z "$($KC get "$authz/policy/search" -r "$REALM" -q name="$policy" 2>/dev/null)" ]; then
  printf '{"name":"%s","description":"The actors allowed to act on behalf of users: the MCP server'"'"'s client","clients":["%s"],"logic":"POSITIVE"}' \
    "$policy" "$actor" | $KC create "$authz/policy/client" -r "$REALM" -f - >/dev/null
  echo "created client policy '$policy'"
else
  echo "client policy '$policy' exists"
fi

permission="delegate to $ACTOR"
if [ -z "$($KC get "$authz/permission/search" -r "$REALM" -q name="$permission" 2>/dev/null)" ]; then
  printf '{"name":"%s","description":"Every user of the realm may be acted for by the policy'"'"'s clients","resourceType":"Users","scopes":["delegate"],"policies":["%s"]}' \
    "$permission" "$policy" | $KC create "$authz/permission/scope" -r "$REALM" -f - >/dev/null
  echo "created permission '$permission' (Users / delegate)"
else
  echo "permission '$permission' exists"
fi
echo "delegation to $ACTOR granted in realm $REALM"
