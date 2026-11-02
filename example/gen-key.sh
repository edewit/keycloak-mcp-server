#!/usr/bin/env sh
# Generates the RSA key the MCP server uses for private_key_jwt (PKCS#8 PEM). Keycloak fetches the matching
# public key from the server's JWKS endpoint, so nothing has to be imported into Keycloak.
set -e
cd "$(dirname "$0")"
if [ -f keys/mcp-jwt.pem ]; then
  echo "keys/mcp-jwt.pem exists"; exit 0
fi
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out keys/mcp-jwt.pem
chmod 600 keys/mcp-jwt.pem
echo "wrote keys/mcp-jwt.pem"
