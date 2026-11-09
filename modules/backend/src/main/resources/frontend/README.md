# Management UI (Lit)

Bundled by [Quarkus Web Bundler](https://docs.quarkiverse.io/quarkus-web-bundler/dev/) during `./mvnw package` /
`quarkus:dev` — no Node or npm.

| path | purpose |
|---|---|
| `app/` | Lit entry (`index.ts`) and components |
| `index.html` | SPA shell with `{#bundle /}`; served for every `/ui/*` route |
| `tsconfig.json` | Lit classic decorators (`experimentalDecorators`) |

Dependencies are Maven (`org.mvnpm:lit`) on the backend module. The BFF the browser calls is `/bff` in this same
module.
