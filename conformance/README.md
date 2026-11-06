# MCP conformance

[modelcontextprotocol/conformance](https://github.com/modelcontextprotocol/conformance) runs protocol scenarios against
an MCP server. This folder holds everything needed to run it against `keycloak-mcp-server`.

```
./mvnw package -DskipTests      # server + conformance/fixtures
conformance/run.sh              # packaged server with the fixtures on :8085, all scenarios, baseline applied
conformance/run.sh --url http://localhost:8081/mcp   # any running server
```

- `run.sh`: starts the packaged server (no Keycloak needed) with the fixture jar in its `providers/` directory, runs
  the suite with the baseline, exits 0 only when nothing unexpected fails. Reports: `results/`, server log
  `results-server.log`.
- `fixtures/`: a Maven module with the `test_*` tools and prompts the suite calls, built as an extension jar for the
  `providers/` directory. Never ship it. It only covers what the tool model expresses: text and error results, prompts.
- `expected-failures.yml`: scenarios this server fails on purpose, one reason each. A scenario that starts passing
  fails the run as a stale baseline entry, so the list stays honest.

## Status

Scenarios that pass: `server-initialize`, `ping`, `logging-set-level`, `tools-list`, `tools-call-simple-text`,
`tools-call-error`, `server-sse-polling`, `server-sse-multiple-streams`, `resources-list`, `prompts-list`,
`prompts-get-simple`, `prompts-get-with-args`, and the localhost half of `dns-rebinding-protection`.

Baselined, by reason:

- Content types the Keycloak tools never produce (image, audio, embedded resource, mixed).
- Client round trips from inside a tool: log and progress notifications, sampling, tool-driven elicitation. The server
  uses elicitation itself for destructive confirmations; the `ToolHandler` SPI has no client channel.
- Resources: none. Realm data is reached through tools.
- `completion/complete`: not declared.
- `json-schema-2020-12`: tool schemas are flat by design for small local models; `InputSchema` has no `$defs`/`$ref`.

## Open finding

`dns-rebinding-protection`: an unauthenticated server bound to localhost accepts requests whose `Host`/`Origin` is not a
localhost value. Relevant for the local LM Studio setup (anonymous endpoint on `localhost:8081`); with
`quarkus.oidc.tenant-enabled=true` every request needs a bearer token and the attack has no effect. A fix is a
Vert.x filter that rejects non-localhost `Host`/`Origin` when the bound address is loopback and the endpoint is
anonymous, off behind a proxy or in containers.

## CI

```yaml
- uses: modelcontextprotocol/conformance@v0.1.16
  with:
    mode: server
    url: http://localhost:8085/mcp
    expected-failures: conformance/expected-failures.yml
```

The server must be started with the fixture jar first (see `run.sh`).
