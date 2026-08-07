import { defineConfig } from "tsup";

// ESM only. The server is a private service, never consumed as a CommonJS library, and an ESM-only
// build keeps `import.meta.url` usable for resolving the migrations directory.
export default defineConfig({
  entry: ["src/index.ts", "src/main.ts"],
  format: ["esm"],
  dts: true,
  splitting: false,
  sourcemap: true,
  clean: true,
  external: ["better-sqlite3"],
});
