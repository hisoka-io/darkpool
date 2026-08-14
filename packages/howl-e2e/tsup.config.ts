import { defineConfig } from "tsup";

// Dual build purely so `packages/evm-contracts`, the CommonJS exception in this workspace, can require the
// discovery harness from its hardhat suite. Workspace and vendor packages stay external: bundling them
// duplicates the crypto and breaks worker-relative paths inside their transitive dependencies.
export default defineConfig({
  entry: { index: "src/index.ts" },
  format: ["cjs", "esm"],
  dts: true,
  sourcemap: true,
  clean: true,
  external: [/^@hisoka\//, /^@aztec\//, /^@zk-kit\//, /^@noble\//],
});
