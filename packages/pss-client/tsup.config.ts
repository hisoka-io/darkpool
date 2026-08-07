import { defineConfig } from "tsup";

// The server imports `./wire` only. Keeping it a separate entry means the wire contract never drags the
// client's crypto backends (noble, WebCrypto) into a process that verifies with node:crypto.
export default defineConfig({
  entry: {
    index: "src/index.ts",
    "wire/index": "src/wire/index.ts",
  },
  format: ["cjs", "esm"],
  dts: true,
  splitting: true,
  sourcemap: true,
  clean: true,
});
