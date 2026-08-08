import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    // A real server process, a real database file and a real chain make these slower than a unit suite.
    testTimeout: 120_000,
    hookTimeout: 120_000,
    // One live server and one database file at a time.
    fileParallelism: false,
  },
});
