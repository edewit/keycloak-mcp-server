# Configuration

`kcmcp.properties` is read on every start (`bin/kcmcp.sh start`); the settings are documented in `docs/configuration.md`.
`scenarios/` holds complete settings for common setups, started with `bin/kcmcp.sh start --config conf/scenarios/<name>.properties`,
which adds that file on top of `kcmcp.properties`; a relative path is taken from the current directory, else from the
distribution's directory. Every setting can also be an environment variable (`kc-mcp.url` →
`KC_MCP_URL`) or a command line option (`--kc-mcp.url=...`).

Private keys for `private_key_jwt` and TLS certificates can live here too; keep the directory readable by the user
the server runs as only.

Without the scripts, the same files are read with `-Dkc-mcp.config-files=<file>,<file>` on the `java -jar` command line.
Settings from the environment and the command line override the files, the files override the server's defaults.
