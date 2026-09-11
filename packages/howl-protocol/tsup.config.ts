import { defineConfig } from "tsup";

export default defineConfig({
  entry: { index: "src/index.ts", "proving/index": "src/proving/index.ts" },
  format: ["esm", "cjs"],
  dts: true,
  splitting: true,
  sourcemap: true,
  clean: true,
});
