import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The API runs on port 8000 unless FALCON_API says otherwise (used to run a second copy for testing).
const api = process.env.FALCON_API ?? "http://localhost:8000";

export default defineConfig({
  plugins: [react()],
  server: { proxy: { "/api": { target: api, rewrite: (p) => p.replace(/^\/api/, "") } } },
});
