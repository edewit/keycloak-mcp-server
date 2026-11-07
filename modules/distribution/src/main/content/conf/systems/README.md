# One file per Keycloak system

Put a `<name>.conf` per system here and start with `bin/kcmcp.sh start --config conf/systems/`: every
`*.conf` file in the directory is read, in name order. Settings a file leaves out fall back to the top-level
ones in `kcmcp.conf` (client id, grant type, ...). For example `prod.conf`:

```properties
kc-mcp.systems.prod.url=https://sso.example.com
kc-mcp.systems.prod.client-secret=${PROD_SECRET}
kc-mcp.systems.prod.allowed-realms=customers,partners
```

With more than one system every tool gets a `system` argument; `kc-mcp.default-system` in `kcmcp.conf` names
the one used when it is left out. See `docs/systems.md`.
