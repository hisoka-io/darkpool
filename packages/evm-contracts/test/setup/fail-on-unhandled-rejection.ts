// Strictness guard loaded before the test suite: a promise rejection or exception that escapes a test
// otherwise lets mocha finish green. Here it prints the error and exits nonzero so CI turns red.
// Idempotent: mocha may load this file more than once (serial file list + parallel worker require).

const GUARD_FLAG = "__hisoka_fail_on_unhandled_rejection__";
const globalWithFlag = globalThis as unknown as Record<string, boolean>;

if (!globalWithFlag[GUARD_FLAG]) {
  globalWithFlag[GUARD_FLAG] = true;

  process.on("unhandledRejection", (reason: unknown) => {
    const err = reason instanceof Error ? reason : new Error(String(reason));
    console.error("unhandledRejection during tests:", err);
    process.exit(1);
  });

  process.on("uncaughtException", (error: unknown) => {
    const err = error instanceof Error ? error : new Error(String(error));
    console.error("uncaughtException during tests:", err);
    process.exit(1);
  });
}
