import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { fileURLToPath } from "node:url";

// The API runs on port 8000 unless FALCON_API says otherwise (used to run a second copy for testing).
const api = process.env.FALCON_API ?? "http://localhost:8000";
// SITE_ONLY=1 builds just the public website (site.html: landing page, no application) into dist-site.
// VITE_BASE is the address path it will be served from, for example /my-site/ on GitHub Pages.
const siteOnly = process.env.SITE_ONLY === "1";

export default defineConfig({
  base: process.env.VITE_BASE ?? "/",
  plugins: [react()],
  resolve: siteOnly ? { alias: [{ find: /^(\.\.?\/)+api\/client$/, replacement: fileURLToPath(new URL("./src/api/siteStub.ts", import.meta.url)) }] } : undefined,
  build: siteOnly ? { outDir: "dist-site", rollupOptions: { input: "site.html" } } : undefined,
  server: { proxy: { "/api": { target: api, rewrite: (p) => p.replace(/^\/api/, "") } } },
});
