# HTTPS and trusted certificates

[keycloak-mcp-server](../README.md) › documentation

The options follow Keycloak's [TLS](https://www.keycloak.org/server/enabletls) and
[truststore](https://www.keycloak.org/server/keycloak-truststore) settings, with the prefix `kc-mcp.`: Keycloak's
`https-certificate-file` is `kc-mcp.https-certificate-file` here, or `KC_MCP_HTTPS_CERTIFICATE_FILE` in the environment.

## HTTPS for the server

A PEM certificate and key:

```properties
kc-mcp.https-certificate-file=${kcmcp.home.dir}/conf/server.crt.pem
kc-mcp.https-certificate-key-file=${kcmcp.home.dir}/conf/server.key.pem
kc-mcp.http-enabled=false
```

or a key store:

```properties
kc-mcp.https-key-store-file=${kcmcp.home.dir}/conf/server.p12
kc-mcp.https-key-store-password=change-me
```

`conf/scenarios/https.conf.example` is a template. Behind a TLS terminating proxy use
`quarkus.http.proxy.proxy-address-forwarding=true` instead ([Configuration](configuration.md)).

| option | default | meaning |
|---|---|---|
| `kc-mcp.https-certificate-file` | | PEM certificate or chain; needs the key file too |
| `kc-mcp.https-certificate-key-file` | | PEM private key |
| `kc-mcp.https-certificate-key-file-password` | | password of an encrypted PKCS#8 key; prefer the environment over a file |
| `kc-mcp.https-key-store-file` | | key store; ignored when a PEM pair is set |
| `kc-mcp.https-key-store-password` | `password` | its password |
| `kc-mcp.https-key-store-type` | from the extension | `PKCS12` (`.p12`, `.pkcs12`, `.pfx`) or `JKS` (`.jks`, `.keystore`) |
| `kc-mcp.https-port` | `8443` | HTTPS port |
| `kc-mcp.http-enabled` | `true` | the plain HTTP listener; `false` leaves HTTPS only |
| `kc-mcp.https-protocols` | `TLSv1.3,TLSv1.2` | protocols to enable |
| `kc-mcp.https-cipher-suites` | the JVM's | cipher suites to enable |
| `kc-mcp.https-certificates-reload-period` | `1h` | how often changed certificate files are picked up without a restart (`30s`, `1h`); `-1` never |

The `quarkus.tls.*` and `quarkus.http.*` properties these become still work, and win if you set them.

The HTTPS listener binds to the same address as HTTP: `127.0.0.1` unless `quarkus.http.host` says otherwise.

## Trusting a private CA

By default the server trusts what the JVM trusts. For a Keycloak behind a private CA, put the CA certificate into
`conf/truststores/` of the distribution and restart. Subdirectories count. Accepted are PEM files (`.pem`, `.crt`,
`.cer`) and unencrypted PKCS12 files (`.p12`, `.pfx`, `.pkcs12`).

Certificates elsewhere are named with a comma-separated list of files or directories:

```properties
kc-mcp.truststore-paths=/etc/pki/my-company-ca.pem,${kcmcp.home.dir}/more-cas
```

A listed path that does not exist, or a file holding no certificates, stops the start. Prefer absolute paths or
`${kcmcp.home.dir}`, a relative path is taken from the working directory. The JVM's default certificates stay trusted.

An unencrypted PKCS12 file from `keytool`:

```shell
keytool -importcert -noprompt -alias my-ca -file my-ca.pem -keystore my-ca.p12 -storetype PKCS12 -storepass unused \
  -J-Dkeystore.pkcs12.certProtectionAlgorithm=NONE -J-Dkeystore.pkcs12.macAlgorithm=NONE
```

The certificates apply to the whole JVM through the `javax.net.ssl.trustStore` properties: the Keycloak admin client,
token verification (OIDC discovery and signing keys), the database driver and anything else that uses the default
trust. A container started without the distribution's scripts has no `conf/truststores`; use `kc-mcp.truststore-paths`
there.

`kc-mcp.ui.tls-configuration-name` and `kc-mcp.spi.ciba-confirmer.tls-configuration-name` still select a separate trust
store for those calls.

## Not supported

Keycloak options without a counterpart: `https-client-auth` and `https-trust-store-*` (client certificates, available
through `quarkus.tls.*`), `tls-hostname-verifier` (hostnames are always checked), `truststore-kubernetes-enabled`,
FIPS, and the automatic `conf/server.keystore`. Unlike Keycloak, plain HTTP is on by default, because local MCP clients
use it.
