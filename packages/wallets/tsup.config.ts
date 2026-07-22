import { defineConfig } from "tsup";

// Three shipped entry points plus one dev/test-only escape hatch. The base UTXO wallet (`.`) never pulls the
// FROST/threshold surface; `./frost` and `./threshold` are opt-in. `./unsafe-sim` bundles the simulated
// ceremony drivers so cross-package tests can drive a full FROST account; it stays off the three shipped
// barrels. `splitting: true` lets the ESM builds share common chunks (tss/crypto) instead of duplicating them.
export default defineConfig({
  entry: {
    index: "src/index.ts",
    reference: "src/reference.ts",
    "frost/index": "src/frost/index.ts",
    "threshold/index": "src/threshold/index.ts",
    "unsafe-sim/index": "src/unsafe-sim/index.ts",
  },
  format: ["cjs", "esm"],
  dts: true,
  splitting: true,
  sourcemap: true,
  clean: true,
});
