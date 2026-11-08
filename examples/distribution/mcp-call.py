#!/usr/bin/env python3
"""Call a tool on an MCP entry: mcp-call.py [--login user:password[@realm]] <entry-url> <tool> [json-arguments]

    ./mcp-call.py http://localhost:9080/mcp/systems/sso whoami
    ./mcp-call.py http://localhost:9080/mcp/systems/sso keycloak_user_search '{"search": "alice"}'
    ./mcp-call.py --login alice:alice-demo http://localhost:9080/mcp/systems/sso/demo whoami

--login fetches a token for the user from Keycloak (http://localhost:8080, public client mcp-consumer, password
grant) in the realm given after @, else the realm of the entry URL, and sends it as a Bearer token: what an MCP
client does after the browser login.
"""
import json
import sys
import urllib.error
import urllib.request
from urllib.parse import urlencode


BEARER = None


def login(spec, url):
    user, _, realm = spec.partition("@")
    username, _, password = user.partition(":")
    if not realm:
        parts = url.rstrip("/").split("/")
        realm = parts[-1] if "/systems/" in url and len(parts) >= 2 and parts[-3] == "systems" else "master"
    # kc-admin-api: the scope Keycloak 26.8.2+ wants on Admin API tokens (older servers ignore it)
    form = urlencode({"grant_type": "password", "client_id": "mcp-consumer", "scope": "kc-admin-api",
                      "username": username, "password": password})
    request = urllib.request.Request(f"http://localhost:8080/realms/{realm}/protocol/openid-connect/token",
                                     form.encode(), {"content-type": "application/x-www-form-urlencoded"})
    with urllib.request.urlopen(request) as response:
        return json.loads(response.read())["access_token"]


def post(url, body, session=None):
    headers = {"content-type": "application/json", "accept": "application/json, text/event-stream"}
    if session:
        headers["mcp-session-id"] = session
    if BEARER:
        headers["authorization"] = "Bearer " + BEARER
    request = urllib.request.Request(url, json.dumps(body).encode(), headers)
    try:
        with urllib.request.urlopen(request) as response:
            session = response.headers.get("mcp-session-id") or session
            raw = response.read().decode()
    except urllib.error.HTTPError as e:
        print(f"HTTP {e.code} {e.reason}; WWW-Authenticate: {e.headers.get('WWW-Authenticate')}")
        sys.exit(1)
    data = None
    for line in raw.splitlines():
        if line.startswith("data:"):
            data = json.loads(line[5:])
    if data is None and raw.strip():
        data = json.loads(raw)
    return session, data


def main():
    global BEARER
    args = sys.argv[1:]
    if args[:1] == ["--login"]:
        spec, args = args[1], args[2:]
        BEARER = login(spec, args[0] if args else "")
    if len(args) < 2:
        print(__doc__)
        sys.exit(2)
    url, tool = args[0], args[1]
    arguments = json.loads(args[2]) if len(args) > 2 else {}
    session, _ = post(url, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "mcp-call", "version": "1"}}})
    post(url, {"jsonrpc": "2.0", "method": "notifications/initialized"}, session)
    _, result = post(url, {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                           "params": {"name": tool, "arguments": arguments}}, session)
    content = result.get("result", result)
    text = content.get("content", [{}])[0].get("text") if isinstance(content, dict) else None
    print(text if text else json.dumps(content, indent=2))


if __name__ == "__main__":
    main()
