# Supported Keycloak versions

[keycloak-mcp-server](../README.md) › documentation

The baseline, how version and feature requirements of tools are checked and explained, and how the tool surface is kept aligned with the Admin REST API of a Keycloak release.

Baseline **Keycloak 26.8** (OpenAPI alignment, integration tests). Newer expected to work; older unchecked. Since
26.8.2 the Admin API requires the `kc-admin-api` client scope on the calling client ([Access levels](security.md#access-levels)).

- At startup and every ten minutes: version and enabled features per system from the admin server info (server
  credentials), kept as a capability snapshot. `kc-mcp.version` / `kc-mcp.systems.<name>.version` override and fill in;
  mismatch logged.
- Tool requirements: `requiresFeatures("organization", ...)` (CLI feature names), `minVersion("26.9")`,
  `maxVersion("26")` (inclusive at the given precision; above it the refusal says "removed"). Organization tools carry
  the feature requirement.
- Unmet requirements explain, never hide:
  - `search_tools`: `allowed=false`, reason `unsupported`
  - call: error `unsupported` + `howToFix` per deployment form (`KC_FEATURE_ORGANIZATION=enabled`,
    `kc.sh start --feature-organization=enabled`, `keycloak.conf`, container, Operator CR, `--features=`), restart note,
    `keycloak_server_features` to verify, <https://www.keycloak.org/server/features>
  - `whoami`: `server` version, baseline, `unavailableTools` by reason, `howToFix`; `keycloak_server_features`:
    `howToEnable` / `howToDisable`
  - startup check: logs version and unavailable tools; below baseline is a problem (`fail` aborts)
- Wording by `kc-mcp.explanations`: `admins` technical + `howToFix`; `users` plain ("the 'organization' feature is
  switched off. A Keycloak administrator can enable it") with a hint to keep it plain; `auto` picks `users` for forward
  callers without master admin or `realm-admin`, else `admins`. Support desk: `KC_MCP_EXPLANATIONS=users`.
- Unknown capabilities never block; Keycloak decides.
- Version differences under one endpoint live in the handler (`call.capabilities()`: `atLeast("26.9")`,
  `hasFeature(...)`), one schema with optional version-specific parameters. Never two `ToolSpec`s with one name: the
  tool list must not depend on the target system.

## Keeping the tools aligned with a Keycloak version

- Every tool declares its Admin REST operations (`ToolSpec.api(...)`, `ApiOperation`): method, path, argument → path/query
  parameter, body fields written.
- `OpenApiAlignmentTest` checks against `src/test/resources/openapi/keycloak-<version>.json` (26.8.2 checked in):
  operation exists, not deprecated, parameters and body fields exist with compatible types/enums. Unexposed spec
  parameters: drift report.
- Server info and user storage sync are missing from the published document: marked `unspecified` with a reason.
- The Java admin client is versioned independently since Keycloak 26.1; this test plus Testcontainers tie the tool
  surface to a server version.

```shell
curl -o src/test/resources/openapi/keycloak-26.9.0.json https://www.keycloak.org/docs-api/26.9.0/rest-api/openapi.json
./mvnw test -Dtest=OpenApiAlignmentTest -Dsurefire.failIfNoSpecifiedTests=false -Dkeycloak.openapi.version=26.9.0
```
