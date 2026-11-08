#!/usr/bin/env bash
# Completes the setup of this example after `docker compose up -d`:
#   1. the server's private_key_jwt key pair (conf/keycloak-mcp-server.pem in the distribution)
#   2. the master realm, which --import-realm cannot touch: the clients mcp-consumer and keycloak-mcp-server, the user
#      root (password root-demo) with the master admin role, the service account with the admin role
# The server configuration stays here in conf/; the start command points at it.
# Idempotent: run it again after `docker compose down -v`.
#
#   ./setup.sh [<unpacked distribution>]      default: ./keycloak-mcp-server-*
set -euo pipefail
cd "$(dirname "$0")"
DIST=${1:-}
if [ -z "$DIST" ]; then # the first unpacked distribution here (a failing ls would end the script silently under set -e)
  for d in keycloak-mcp-server-*/; do [ -d "$d" ] && DIST=$d && break; done
fi
[ -n "$DIST" ] && [ -d "$DIST" ] || { echo "no distribution found${1:+ at $1}: unpack it here first (tar xzf keycloak-mcp-server-*.tar.gz)" >&2; exit 2; }
DIST=${DIST%/}
KCADM="docker compose exec -T keycloak /opt/keycloak/bin/kcadm.sh"

echo "== 1. the server's key: $DIST/conf/keycloak-mcp-server.pem"
if [ ! -f "$DIST/conf/keycloak-mcp-server.pem" ]; then
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$DIST/conf/keycloak-mcp-server.pem" 2>/dev/null
  chmod 600 "$DIST/conf/keycloak-mcp-server.pem"
  echo "generated"
else
  echo "exists"
fi

echo "== 2. the master realm"
for _ in $(seq 1 60); do curl -sf http://localhost:8080/realms/master > /dev/null && break; sleep 2; done
curl -sf http://localhost:8080/realms/master > /dev/null || { echo "Keycloak is not up on :8080 (docker compose up -d)" >&2; exit 1; }
$KCADM config credentials --server http://localhost:8080 --realm master --user admin --password admin > /dev/null

client_id() { $KCADM get clients -r master -q clientId="$1" --fields id --format csv --noquotes | head -1; }

ID=$(client_id keycloak-mcp-server || true)
if [ -z "$ID" ]; then
  $KCADM create clients -r master -f - < clients/master-keycloak-mcp-server.json > /dev/null
  echo "created client keycloak-mcp-server (Signed JWT, JWKS URL http://host.docker.internal:9080/.well-known/jwks.json)"
else
  echo "client keycloak-mcp-server exists"
fi
# the service account administers every realm of this Keycloak ...
$KCADM add-roles -r master --uusername service-account-keycloak-mcp-server --rolename admin 2> /dev/null || true
# ... and, full scope being off, the client's role scope lets the admin role into its tokens
scope_admin() { # $1 client id (uuid)
  $KCADM get roles/admin -r master --fields id,name | sed 's/^{/[{/; s/}$/}]/' \
    | $KCADM create "clients/$1/scope-mappings/realm" -r master -f - > /dev/null 2>&1 || true
}
scope_admin "$(client_id keycloak-mcp-server)"

ID=$(client_id mcp-consumer || true)
if [ -z "$ID" ]; then
  $KCADM create clients -r master -f - < clients/master-mcp-consumer.json > /dev/null
  echo "created client mcp-consumer (public, PKCE, aud=keycloak-mcp-server)"
else
  echo "client mcp-consumer exists"
fi

if ! $KCADM get users -r master -q username=root --fields username --format csv --noquotes | grep -qx root; then
  $KCADM create users -r master -s username=root -s enabled=true -s firstName=Root -s lastName=Admin -s email=root@example.com -s emailVerified=true > /dev/null
  $KCADM set-password -r master --username root --new-password root-demo
  echo "created user root / root-demo"
else
  echo "user root exists"
fi
$KCADM add-roles -r master --uusername root --rolename admin 2> /dev/null || true
# the admin role in mcp-consumer's role scope: root's token carries it (full scope off)
scope_admin "$(client_id mcp-consumer)"
echo "root holds master/admin: administers every realm"

# Keycloak fetches the server's JWKS as host.docker.internal:9080. Docker Desktop (macOS, Windows) reaches the
# server's loopback listener that way; on Linux the name is the bridge gateway, which does not.
if [ "$(uname -s)" = Linux ] && ! grep -q '^quarkus.http.host=' conf/server.conf; then
  echo
  if grep -qi microsoft /proc/version 2>/dev/null; then
    echo "NOTE: WSL. If Keycloak cannot fetch the JWKS (the login fails with 'invalid_client' / 'Client authentication"
    echo "      with signed JWT failed'), uncomment quarkus.http.host=0.0.0.0 in conf/server.conf."
  else
    echo "WARNING: Linux. The server listens on 127.0.0.1, which the Keycloak container cannot reach as"
    echo "         host.docker.internal: uncomment quarkus.http.host=0.0.0.0 in conf/server.conf before starting it."
  fi
fi
echo
echo "Next: cd $DIST && bin/kcmcp.sh start --config ../conf/server.conf --config ../conf/systems/"
