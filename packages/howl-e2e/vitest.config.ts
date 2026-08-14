import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    // Real proofs and a real chain, so these are minutes rather than milliseconds.
    testTimeout: 600_000,
    hookTimeout: 600_000,
    fileParallelism: false,
  },
});
