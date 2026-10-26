import { defineConfig } from "tsup";

// Workspace and vendor packages stay external: bundling them would duplicate the crypto and the `Fr`
// class, so an `instanceof` across the boundary would fail.
export default defineConfig({
  entry: { index: "src/index.ts" },
  format: ["cjs", "esm"],
  dts: true,
  sourcemap: true,
  clean: true,
  external: [/^@hisoka\//, /^@aztec\//, /^@zk-kit\//],
});
