# Trusted certificates

Certificates in this directory and its subdirectories are trusted for the server's outgoing TLS connections, in
addition to the JVM's default certificates: PEM files (`.pem`, `.crt`, `.cer`) and unencrypted PKCS12 files (`.p12`,
`.pfx`, `.pkcs12`). Put the private CA of your Keycloak here and restart. See `docs/tls.md`.
