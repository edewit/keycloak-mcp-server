import { defineConfig } from 'vite';
import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';

// The app is served by the backend at /ui/; the Maven build sets KC_MCP_UI_OUT_DIR to the jar's resource directory
// (target/classes/META-INF/resources/ui), which emptyOutDir clears before every build.
const outDir = process.env.KC_MCP_UI_OUT_DIR ?? resolve(__dirname, 'dist');

// `npm run dev`: Vite on https://localhost:5173 with the mkcert certificates of the repository (etc/mkcert.sh), the
// BFF proxied to the running server so the session cookie is first-party. Keycloak must know
// https://localhost:5173/bff/login as a redirect URI (the demo realm does).
const certs = resolve(__dirname, '../../../../.certs');
const cert = resolve(certs, 'localhost.pem');
const key = resolve(certs, 'localhost-key.pem');
const https = existsSync(cert) && existsSync(key) ? { cert: readFileSync(cert), key: readFileSync(key) } : undefined;
if (!https && process.argv.includes('dev')) {
  console.warn('No .certs/localhost.pem: run etc/mkcert.sh first, the Secure session cookie needs https');
}
const backend = process.env.KC_MCP_UI_BACKEND ?? 'https://localhost:8443';

export default defineConfig({
  base: '/ui/',
  build: { outDir, emptyOutDir: true, sourcemap: true },
  server: {
    port: 5173,
    https,
    open: '/ui/',
    proxy: {
      '/bff': { target: backend, secure: false, changeOrigin: false },
    },
  },
});
