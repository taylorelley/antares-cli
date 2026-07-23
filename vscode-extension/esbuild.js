"use strict";

const esbuild = require("esbuild");
const fs = require("fs");

const production = process.argv.includes("--production");
const watch = process.argv.includes("--watch");

async function main() {
  // Start from a clean dist/ so stale dev sourcemaps never ship in the VSIX.
  fs.rmSync("dist", { recursive: true, force: true });

  const context = await esbuild.context({
    // Two entry points: the extension host bundle and the worker-thread engine.
    entryPoints: { extension: "src/extension.ts", worker: "src/engine/worker.ts" },
    bundle: true,
    format: "cjs",
    minify: production,
    sourcemap: !production,
    sourcesContent: false,
    platform: "node",
    target: "node18",
    outdir: "dist",
    // The `vscode` module is provided by the extension host at runtime.
    external: ["vscode"],
    logLevel: "info",
  });

  if (watch) {
    await context.watch();
  } else {
    await context.rebuild();
    await context.dispose();
  }
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
