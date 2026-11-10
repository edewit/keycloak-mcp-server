#!/usr/bin/env python3
"""Stand-in enterprise IdP for Cross-App Access (ID-JAG), standard library only. Demo code, not an IdP.

Keycloak accepts ID-JAGs (identity-assertion-jwt, experimental) but cannot issue them yet (keycloak#48818). This
server plays the enterprise IdP:
  - sign-in: password grant for the users in policy.json, answers an ID token (a real IdP: browser SSO)
  - token exchange (RFC 8693, draft-ietf-oauth-identity-assertion-authz-grant): subject_token = that ID token,
    requested_token_type = ...:id-jag, audience = issuer of the app's authorization server, resource = the app;
    answers an ID-JAG (typ oauth-id-jag+jwt, 5 minutes) if policy.json lets this user reach the app via this client
  - /jwks, /.well-known/openid-configuration: what Keycloak verifies the ID-JAG with

policy.json is read on every request: edit it, no restart. Without --key the signing key lives in memory and changes
with every start (Keycloak fetches the new one on the unknown kid).

  python3 idp.py [--port 8102] [--issuer http://localhost:8102] [--policy policy.json] [--key key.json]
"""
import argparse
import base64
import hashlib
import json
import secrets
import sys
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ID_JAG = "urn:ietf:params:oauth:token-type:id-jag"
ID_TOKEN = "urn:ietf:params:oauth:token-type:id_token"
TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"


# --- RS256 without dependencies -------------------------------------------------------------------------------------

def _probable_prime(bits):
    while True:
        n = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if all(n % p for p in (3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)) and _miller_rabin(n):
            return n


def _miller_rabin(n, rounds=40):
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(rounds):
        x = pow(secrets.randbelow(n - 3) + 2, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_key(bits=2048):
    e = 65537
    while True:
        p, q = _probable_prime(bits // 2), _probable_prime(bits // 2)
        phi = (p - 1) * (q - 1)
        if p != q and phi % e:
            n = p * q
            return {"n": n, "e": e, "d": pow(e, -1, phi), "kid": secrets.token_hex(8)}


def load_key(path):
    if path is None:
        return generate_key()
    if path.exists():
        k = json.loads(path.read_text())
        return {"n": int(k["n"]), "e": int(k["e"]), "d": int(k["d"]), "kid": k["kid"]}
    k = generate_key()
    path.write_text(json.dumps({kk: str(v) for kk, v in k.items()}))
    return k


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def int_bytes(i):
    return i.to_bytes((i.bit_length() + 7) // 8, "big")


SHA256_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")


def _emsa(msg, k):
    size = (k["n"].bit_length() + 7) // 8
    t = SHA256_PREFIX + hashlib.sha256(msg).digest()
    return int.from_bytes(b"\x00\x01" + b"\xff" * (size - len(t) - 3) + b"\x00" + t, "big"), size


def sign(header, claims, k):
    signing_input = f"{b64url(json.dumps(header).encode())}.{b64url(json.dumps(claims).encode())}".encode()
    m, size = _emsa(signing_input, k)
    return signing_input.decode() + "." + b64url(pow(m, k["d"], k["n"]).to_bytes(size, "big"))


def verify(token, k):
    """Verify one of our own tokens; returns the claims or None."""
    try:
        h, c, s = token.split(".")
        header = json.loads(b64url_decode(h))
        m, _ = _emsa(f"{h}.{c}".encode(), k)
        if header.get("alg") != "RS256" or pow(int.from_bytes(b64url_decode(s), "big"), k["e"], k["n"]) != m:
            return None
        return header, json.loads(b64url_decode(c))
    except Exception:
        return None


def jwks(k):
    return {"keys": [{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": k["kid"],
                      "n": b64url(int_bytes(k["n"])), "e": b64url(int_bytes(k["e"]))}]}


# --- the IdP --------------------------------------------------------------------------------------------------------

class Idp:
    def __init__(self, issuer, policy, key):
        self.issuer, self.policy_path, self.key = issuer.rstrip("/"), policy, key

    @property
    def policy(self):  # re-read on every request: edit policy.json, no restart
        return json.loads(self.policy_path.read_text())

    def client(self, form, auth_header):
        cid, secret = form.get("client_id"), form.get("client_secret")
        if auth_header and auth_header.startswith("Basic "):
            cid, _, secret = base64.b64decode(auth_header[6:]).decode().partition(":")
            cid, secret = urllib.parse.unquote(cid), urllib.parse.unquote(secret)
        c = self.policy["clients"].get(cid or "")
        return (cid, c) if c and secrets.compare_digest(c["secret"], secret or "") else (None, None)

    def token(self, form, auth_header):
        cid, client = self.client(form, auth_header)
        if not client:
            return 401, {"error": "invalid_client"}
        grant = form.get("grant_type")
        if grant == "password":
            return self.login(cid, form)
        if grant == TOKEN_EXCHANGE:
            return self.exchange(cid, client, form)
        return 400, {"error": "unsupported_grant_type"}

    def login(self, cid, form):
        """Stands in for the SSO login of the MCP client (a browser flow in a real IdP)."""
        user = self.policy["users"].get(form.get("username", ""))
        if not user or not secrets.compare_digest(user["password"], form.get("password", "")):
            return 400, {"error": "invalid_grant", "error_description": "invalid user credentials"}
        now = int(time.time())
        claims = {"iss": self.issuer, "sub": user["sub"], "aud": cid, "iat": now, "exp": now + 600,
                  "auth_time": now, "email": user.get("email"), "preferred_username": form["username"],
                  "groups": user.get("groups", [])}
        id_token = sign({"alg": "RS256", "typ": "JWT", "kid": self.key["kid"]}, claims, self.key)
        return 200, {"id_token": id_token, "token_type": "N_A", "expires_in": 600}

    def exchange(self, cid, client, form):
        if form.get("requested_token_type") != ID_JAG:
            return 400, {"error": "invalid_request", "error_description": f"requested_token_type must be {ID_JAG}"}
        if form.get("subject_token_type") != ID_TOKEN:
            return 400, {"error": "invalid_request", "error_description": f"subject_token_type must be {ID_TOKEN}"}
        verified = verify(form.get("subject_token", ""), self.key)
        if not verified:
            return 400, {"error": "invalid_grant", "error_description": "subject_token is not an ID token of this IdP"}
        _, id_claims = verified
        if id_claims.get("aud") != cid or id_claims.get("exp", 0) < time.time():
            return 400, {"error": "invalid_grant", "error_description": "subject_token expired or issued to another client"}
        audience, resource = form.get("audience"), form.get("resource")
        app = next((a for a in self.policy["apps"]
                    if a["audience"] == audience and (resource is None or resource == a["resource"])), None)
        if not app:
            return 400, {"error": "invalid_target", "error_description": "no app with this audience and resource"}
        groups = set(id_claims.get("groups", []))
        if cid not in app["clients"] or not groups & set(app["groups"]):
            # the admin's decision: this user (via this client) may not reach this app
            print(f"ID-JAG for {id_claims.get('preferred_username')} via {cid} -> {app['resource']} refused by policy",
                  file=sys.stderr)
            return 400, {"error": "access_denied",
                         "error_description": f"policy: {cid} may not reach {app['resource']} for this user"}
        requested = (form.get("scope") or app.get("default_scope", "")).split()
        allowed = [s for s in requested if s in app.get("scopes", [])]
        now = int(time.time())
        claims = {"iss": self.issuer, "sub": id_claims["sub"], "aud": audience,
                  "client_id": app["clients"][cid], "resource": app["resource"], "jti": secrets.token_hex(16),
                  "iat": now, "exp": now + 300, "auth_time": id_claims.get("auth_time"),
                  "email": id_claims.get("email")}
        if allowed:
            claims["scope"] = " ".join(allowed)
        id_jag = sign({"alg": "RS256", "typ": "oauth-id-jag+jwt", "kid": self.key["kid"]}, claims, self.key)
        print(f"ID-JAG for {id_claims.get('preferred_username')} via {cid} -> {app['resource']} "
              f"scope={claims.get('scope', '')!r}", file=sys.stderr)
        return 200, {"access_token": id_jag, "issued_token_type": ID_JAG, "token_type": "N_A",
                     "expires_in": 300, **({"scope": claims["scope"]} if allowed else {})}

    def metadata(self):
        return {"issuer": self.issuer, "token_endpoint": f"{self.issuer}/token", "jwks_uri": f"{self.issuer}/jwks",
                "grant_types_supported": ["password", TOKEN_EXCHANGE],
                "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
                "id_token_signing_alg_values_supported": ["RS256"], "subject_types_supported": ["public"],
                "response_types_supported": ["id_token"],
                # never used: Keycloak's identity provider config wants an authorization URL
                "authorization_endpoint": f"{self.issuer}/authorize"}


def handler(idp):
    class H(BaseHTTPRequestHandler):
        def send(self, status, body):
            data = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            path = urllib.parse.urlparse(self.path).path
            if path in ("/.well-known/openid-configuration", "/.well-known/oauth-authorization-server"):
                self.send(200, idp.metadata())
            elif path == "/jwks":
                self.send(200, jwks(idp.key))
            else:
                self.send(404, {"error": "not_found"})

        def do_POST(self):
            if urllib.parse.urlparse(self.path).path != "/token":
                return self.send(404, {"error": "not_found"})
            body = self.rfile.read(int(self.headers.get("Content-Length", 0))).decode()
            form = {k: v[0] for k, v in urllib.parse.parse_qs(body).items()}
            self.send(*idp.token(form, self.headers.get("Authorization")))

        def log_message(self, fmt, *args):
            print(f"{self.command} {self.path} -> {args[1] if len(args) > 1 else ''}", file=sys.stderr)

    return H


def main():
    here = Path(__file__).resolve().parent
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8102)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--issuer", default="http://localhost:8102")
    ap.add_argument("--policy", type=Path, default=here / "policy.json")
    ap.add_argument("--key", type=Path, help="keep the signing key in this file (created on first start)")
    a = ap.parse_args()
    idp = Idp(a.issuer, a.policy, load_key(a.key))
    print(f"enterprise IdP {idp.issuer} on {a.host}:{a.port}, policy {a.policy}", file=sys.stderr)
    ThreadingHTTPServer((a.host, a.port), handler(idp)).serve_forever()


if __name__ == "__main__":
    main()
