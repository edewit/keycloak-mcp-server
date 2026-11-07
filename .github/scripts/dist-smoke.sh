#!/usr/bin/env bash
# Smoke test of the unpacked distribution, as the CI's distribution job runs it on Linux (and by hand):
#
#   .github/scripts/dist-smoke.sh <unpacked distribution> [<realm import file>]
#
# Starts the server with bin/kcmcp.sh from a directory other than the distribution's, with a --config file given as a
# relative path, and initializes an MCP session. With a realm file, also starts Keycloak 26.8.2 in Docker with that
# realm imported, starts the server again with the service-account scenario against it, and runs keycloak_user_search
# through the MCP protocol: the packaged server administering a real Keycloak.
set -euo pipefail
DIST=$1
REALM=${2:-}
PORT=${PORT:-8085}
KC_PORT=${KC_PORT:-18080}
KC_IMAGE=${KC_IMAGE:-quay.io/keycloak/keycloak:26.8.2}
INIT='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"smoke","version":"0"}}}'

SERVER_PID=""
KC_ID=""
cleanup() {
  [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null && wait "$SERVER_PID" 2>/dev/null || true
  [ -n "$KC_ID" ] && docker rm -f "$KC_ID" >/dev/null 2>&1 || true
}
trap cleanup EXIT

mcp() { # $1 body, $2 session id or empty; prints the answer (JSON or SSE), the session id goes to .session
  curl -sS -D headers.txt -X POST "http://localhost:$PORT/mcp" -H 'Content-Type: application/json' \
    -H 'Accept: application/json, text/event-stream' ${2:+-H "Mcp-Session-Id: $2"} -d "$1"
  sed -n 's/^[Mm]cp-[Ss]ession-[Ii]d: *//p' headers.txt | tr -d '\r' > .session
}

start_server() { # $@ server options; waits for the MCP endpoint
  "$DIST/bin/kcmcp.sh" start "$@" > server.log 2>&1 &
  SERVER_PID=$!
  for _ in $(seq 1 60); do
    if mcp "$INIT" "" > init.json 2>/dev/null && grep -q '"serverInfo"' init.json; then return 0; fi
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then break; fi
    sleep 1
  done
  echo "the server did not come up:"; cat server.log; exit 1
}

stop_server() { kill "$SERVER_PID"; wait "$SERVER_PID" 2>/dev/null || true; SERVER_PID=""; }

echo "== version"; "$DIST/bin/kcmcp.sh" --version

echo "== 1. a --config file by relative path, from outside the distribution"
printf 'quarkus.http.port=%s\nkc-mcp.tool-exposure=lazy\n' "$PORT" > "$DIST/conf/smoke.properties"
start_server --config conf/smoke.properties --kc-mcp.startup-check=off --kc-mcp.url=http://127.0.0.1:1 \
  --kc-mcp.client-id=smoke --kc-mcp.client-secret=smoke
grep -q 'exposure=LAZY' server.log || { echo "conf/smoke.properties was not read"; cat server.log; exit 1; }
echo "session $(cat .session), exposure lazy: ok"
stop_server

if [ -z "$REALM" ]; then exit 0; fi

echo "== 2. Keycloak $KC_IMAGE with the realm $REALM"
KC_ID=$(docker run -d --rm -p "$KC_PORT:8080" -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
  -e KC_FEATURES=identity-brokering-api:v2 -e KC_FEATURES_DISABLED=twitter-broker \
  -v "$(cd "$(dirname "$REALM")" && pwd)/$(basename "$REALM"):/opt/keycloak/data/import/realm.json:ro" \
  "$KC_IMAGE" start-dev --import-realm)
for _ in $(seq 1 120); do curl -sf "http://localhost:$KC_PORT/realms/demo" > /dev/null && break; sleep 2; done
curl -sf "http://localhost:$KC_PORT/realms/demo" > /dev/null || { docker logs "$KC_ID" | tail -20; exit 1; }

echo "== 3. the service-account scenario against it, keycloak_user_search over MCP"
start_server --config conf/scenarios/service-account.properties --quarkus.http.port="$PORT" \
  --kc-mcp.url="http://localhost:$KC_PORT" --kc-mcp.client-secret=mcp-admin-secret
SESSION=$(cat .session)
mcp '{"jsonrpc":"2.0","method":"notifications/initialized"}' "$SESSION" > /dev/null
mcp '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"keycloak_user_search","arguments":{"search":"alice"}}}' "$SESSION" > search.out
grep -q '"username"' search.out && grep -q 'alice' search.out || { echo "unexpected answer:"; cat search.out; cat server.log; exit 1; }
grep -q 'tool=keycloak_user_search .*outcome=ok' server.log || { echo "no audit line"; cat server.log; exit 1; }
echo "alice found through the packaged server: ok"
