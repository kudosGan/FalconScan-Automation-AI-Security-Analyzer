// Builds the public website (landing page only) into dist-site, ready to upload to any static host such as GitHub Pages.
//   VITE_BASE=/repo-name/ npm run build:site
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

const out = "dist-site";
fs.rmSync(out, { recursive: true, force: true });
const r = spawnSync("npx", ["vite", "build"], { stdio: "inherit", shell: true, env: { ...process.env, SITE_ONLY: "1" } });
if (r.status !== 0) process.exit(r.status ?? 1);
fs.renameSync(path.join(out, "site.html"), path.join(out, "index.html"));
fs.copyFileSync(path.join(out, "index.html"), path.join(out, "404.html"));   // a page address opened directly still loads the site
fs.writeFileSync(path.join(out, ".nojekyll"), "");                           // GitHub Pages: serve the files as they are
console.log(`Public website ready in ${out}/ (${fs.readdirSync(out).length} items at the top level).`);
