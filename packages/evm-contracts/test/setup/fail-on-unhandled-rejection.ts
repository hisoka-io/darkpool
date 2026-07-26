// A rejection escaping a test otherwise lets mocha finish green; exit nonzero. Idempotent: mocha may load this file more than once.

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
