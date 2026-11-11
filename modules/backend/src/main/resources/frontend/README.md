# Management UI (Lit)

Bundled by [Quarkus Web Bundler](https://docs.quarkiverse.io/quarkus-web-bundler/dev/) during `./mvnw package` /
`quarkus:dev` — no Node or npm. `quarkus.web-bundler.web-root=frontend`.

| path | purpose |
|---|---|
| `app/` | Lit entry (`index.ts`) and components |
| `index.html` | Document shell: layout + sibling components (`session`, `toolbar`, `nav`, `outlet`) + `{#bundle /}` |
| `tsconfig.json` | Lit classic decorators (`experimentalDecorators`) |

A `-Pdist` build bundles these same files in `modules/ui-bundle` and ships the result as a static jar, because
Web Bundler cannot run when `bin/kcmcp.sh build` re-augments an unpacked distribution.

Dependencies are Maven (`org.mvnpm:lit`, `org.mvnpm.at.lit:context`, `org.mvnpm.at.lit-labs:router`,
`org.mvnpm:urlpattern-polyfill`) on the backend module (and ui-bundle). `index.html` declares the shell as sibling
custom elements; `kc-mcp-session` provides Lit context in light DOM, and toolbar / nav / outlet each update on their
own. The BFF the browser calls is `/bff` in this same module.
