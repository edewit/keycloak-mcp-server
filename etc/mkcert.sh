#!/usr/bin/env bash
# Local HTTPS for the management UI with mkcert (https://github.com/FiloSottile/mkcert, `brew install mkcert`):
# installs mkcert's CA in the local trust stores once and writes a certificate for localhost into .certs/ (git-ignored).
#
#   etc/mkcert.sh [more host names]
#
# The server picks the files up with
#   QUARKUS_TLS_KEY_STORE_PEM_UI_CERT=.certs/localhost.pem QUARKUS_TLS_KEY_STORE_PEM_UI_KEY=.certs/localhost-key.pem
# and the Vite dev server of modules/frontend reads them from the same place.
set -euo pipefail
cd "$(dirname "$0")/.."
command -v mkcert >/dev/null || { echo "mkcert not found: brew install mkcert (and nss for Firefox)"; exit 1; }
mkdir -p .certs
mkcert -install
mkcert -cert-file .certs/localhost.pem -key-file .certs/localhost-key.pem localhost 127.0.0.1 ::1 "$@"
echo "wrote .certs/localhost.pem and .certs/localhost-key.pem (CA: $(mkcert -CAROOT))"
