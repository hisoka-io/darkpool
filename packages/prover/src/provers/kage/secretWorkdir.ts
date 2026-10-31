import { spawn, type ChildProcess } from "node:child_process";
import { chmodSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

/**
 * Scratch directories that hold secret witness bytes (the maker's spend scalar) for a native prove.
 *
 * Each directory is mode 0700 and is removed when its job settles, on `exit`, and on SIGINT/SIGTERM, which
 * also kill any native child still reading it. SIGKILL and power loss cannot be caught: run the solver with a
 * tmpfs-backed `TMPDIR` so nothing reaches persistent storage.
 */
const liveDirs = new Set<string>();
const liveChildren = new Set<ChildProcess>();
const SIGNALS = ["SIGINT", "SIGTERM"] as const;
type HandledSignal = (typeof SIGNALS)[number];
let armed = false;

function scrub(): void {
  for (const child of liveChildren) child.kill("SIGKILL");
  for (const dir of liveDirs) rmSync(dir, { recursive: true, force: true });
  liveDirs.clear();
}

function onExit(): void {
  scrub();
}

function onSignal(signal: HandledSignal): void {
  scrub();
  disarm();
  // A listener suppresses the default action; re-raise unless the host installed its own handler.
  if (process.listenerCount(signal) === 0) process.kill(process.pid, signal);
}

function arm(): void {
  if (armed) return;
  armed = true;
  process.on("exit", onExit);
  for (const signal of SIGNALS) process.on(signal, onSignal);
}

function disarm(): void {
  if (!armed) return;
  armed = false;
  process.off("exit", onExit);
  for (const signal of SIGNALS) process.off(signal, onSignal);
}

function release(dir: string): void {
  rmSync(dir, { recursive: true, force: true });
  liveDirs.delete(dir);
  if (liveDirs.size === 0 && liveChildren.size === 0) disarm();
}

export async function withSecretWorkdir<T>(
  prefix: string,
  job: (dir: string) => Promise<T>,
): Promise<T> {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  liveDirs.add(dir);
  arm();
  try {
    chmodSync(dir, 0o700);
    return await job(dir);
  } finally {
    release(dir);
  }
}

export class NativeRunError extends Error {
  constructor(
    readonly command: string,
    readonly exitCode: number | null,
    readonly signal: NodeJS.Signals | null,
    readonly output: string,
  ) {
    super(
      `${command} exited ${exitCode ?? `on ${signal ?? "unknown signal"}`}: ${output.trim()}`,
    );
    this.name = "NativeRunError";
  }
}

/** Runs a native binary without blocking the event loop, so the signal handlers above stay live during it. */
export function runNative(binary: string, args: string[]): Promise<string> {
  return new Promise((resolve, reject) => {
    const child = spawn(binary, args, { stdio: ["ignore", "pipe", "pipe"] });
    liveChildren.add(child);
    const chunks: Buffer[] = [];
    child.stdout.on("data", (b: Buffer) => chunks.push(b));
    child.stderr.on("data", (b: Buffer) => chunks.push(b));
    const command = `${binary} ${args[0] ?? ""}`.trim();
    child.on("error", (err) => {
      liveChildren.delete(child);
      reject(new NativeRunError(command, null, null, err.message));
    });
    child.on("close", (code, signal) => {
      liveChildren.delete(child);
      const output = Buffer.concat(chunks).toString("utf8");
      if (code === 0) resolve(output);
      else reject(new NativeRunError(command, code, signal, output));
    });
  });
}
