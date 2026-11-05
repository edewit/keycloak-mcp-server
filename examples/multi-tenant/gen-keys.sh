#!/bin/sh
# Provisions the MCP server's private_key_jwt key per tenant (PKCS#8 PEM, what the read-only file vault reads).
# In production this is the control plane's or operations' job; the matching public key is served by the MCP
# server at /auth/keys/<tenant>/jwks.json. Run once; existing keys are kept.
set -e
cd "$(dirname "$0")/keys"
for tenant in tenant-a tenant-b; do
  if [ -f "$tenant.pem" ]; then echo "$tenant.pem exists"; continue; fi
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$tenant.pem" 2>/dev/null
  chmod 600 "$tenant.pem"
  echo "generated $tenant.pem"
done
