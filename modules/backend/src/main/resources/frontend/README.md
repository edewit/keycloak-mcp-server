# Management UI (Lit)

Bundled by [Quarkus Web Bundler](https://docs.quarkiverse.io/quarkus-web-bundler/dev/) during `./mvnw package` /
`quarkus:dev` — no Node or npm.

| path | purpose |
|---|---|
| `app/` | Lit entry (`index.ts`) and components |
| `index.html` | SPA shell with `{#bundle /}`; served for every `/ui/*` route |
| `tsconfig.json` | Lit classic decorators (`experimentalDecorators`) |

A `-Pdist` build bundles these same files in `modules/ui-bundle` and ships the result as a static jar, because
Web Bundler cannot run when `bin/kcmcp.sh build` re-augments an unpacked distribution.

Dependencies are Maven (`org.mvnpm:lit`) on the backend module. The BFF the browser calls is `/bff` in this same
module.
