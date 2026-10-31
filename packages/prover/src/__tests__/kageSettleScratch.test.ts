/**
 * The solver-side guards around the native swap_settle prove, run against a stand-in `bb` so they need no
 * native toolchain: the intent-key check refuses a foreign key before bb is ever invoked, and the scratch
 * directory holding the maker's spend scalar never outlives the prove (success, failure, SIGTERM, exit).
 */
import {
  describe,
  it,
  expect,
  beforeAll,
  afterAll,
  afterEach,
  vi,
} from "vitest";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { SwapIntentProof, SwapSettleInputs } from "../types.js";
import { EXPECTED_RETURN, swapFixture } from "./fixtures/kageSwap.js";

const work = mkdtempSync(join(tmpdir(), "kage-settle-guards-"));
const fakeBb = join(work, "bb");
const bbLog = join(work, "bb.log");
const proveStarted = join(work, "prove.started");
const scratch = join(work, "tmp");
mkdirSync(scratch);

// Argument positions follow settleNative: prove -b <bytecode> -w <witness> -o <out> -t evm --write_vk.
writeFileSync(
  fakeBb,
  `#!/bin/sh
echo "$1" >> "$FAKE_BB_LOG"
case "$1" in
  --version) echo 5.0.0 ;;
  prove)
    stat -c '%a' "$(dirname "$5")" "$5" >> "$FAKE_BB_LOG"
    case "$FAKE_BB_MODE" in
      fail) echo "Builder failure when we have real witnesses" >&2; exit 1 ;;
      hang) echo $$ > "$FAKE_BB_MARK"; exec sleep 60 ;;
    esac
    mkdir -p "$7"
    head -c $((322 * 32)) /dev/zero > "$7/proof"
    head -c $((42 * 32)) /dev/zero > "$7/public_inputs"
    : > "$7/vk" ;;
  verify) exit 0 ;;
esac
`,
  { mode: 0o755 },
);

process.env.BB_NATIVE_PATH = fakeBb;
process.env.FAKE_BB_LOG = bbLog;
process.env.FAKE_BB_MARK = proveStarted;
const savedTmp = process.env.TMPDIR;

// config.ts reads BB_NATIVE_PATH at import, so the provers load after the stand-in is in place.
const { proveSwapIntent } = await import("../provers/kage/swapIntent.js");
const { proveSwapSettle, IntentVkMismatchError } =
  await import("../provers/kage/swapSettle.js");
const { ProofError } = await import("../errors.js");

const bbCalls = (): string[] =>
  existsSync(bbLog) ? readFileSync(bbLog, "utf8").trim().split("\n") : [];

async function untilProveStarts(): Promise<number> {
  for (let i = 0; i < 600; i++) {
    if (existsSync(proveStarted)) {
      const pid = readFileSync(proveStarted, "utf8").trim();
      if (pid) return Number(pid);
    }
    await new Promise((r) => setTimeout(r, 50));
  }
  throw new Error("stand-in bb prove never started");
}

function isAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

function newListener(
  event: "SIGTERM" | "exit",
  before: ReadonlyArray<(...args: never[]) => void>,
): (arg: string | number) => void {
  const added = process
    .listeners(event)
    .filter((l) => !before.includes(l as (...args: never[]) => void));
  expect(added).toHaveLength(1);
  return added[0] as (arg: string | number) => void;
}

describe("swap_settle solver guards", () => {
  let intent: SwapIntentProof;
  let mb: Omit<SwapSettleInputs, "intent">;

  beforeAll(async () => {
    const fixture = await swapFixture();
    intent = await proveSwapIntent(fixture.intentInputs);
    mb = await fixture.maker(EXPECTED_RETURN);
    process.env.TMPDIR = scratch;
  }, 300_000);

  afterEach(() => {
    rmSync(bbLog, { force: true });
    rmSync(proveStarted, { force: true });
    delete process.env.FAKE_BB_MODE;
  });

  afterAll(() => {
    if (savedTmp === undefined) delete process.env.TMPDIR;
    else process.env.TMPDIR = savedTmp;
    rmSync(work, { recursive: true, force: true });
  });

  it("refuses an intent under a foreign key before invoking native bb", async () => {
    const forgedHash = { ...intent, vkHash: "0x" + "11".repeat(32) };
    await expect(
      proveSwapSettle({ ...mb, intent: forgedHash }),
    ).rejects.toThrow(IntentVkMismatchError);

    const vkAsFields = [...intent.vkAsFields];
    vkAsFields[10] = "0x" + (BigInt(vkAsFields[10]) ^ 1n).toString(16);
    await expect(
      proveSwapSettle({ ...mb, intent: { ...intent, vkAsFields } }),
    ).rejects.toThrow(/verification key field 10 differs/);

    await expect(
      proveSwapSettle({
        ...mb,
        intent: { ...intent, vkAsFields: intent.vkAsFields.slice(1) },
      }),
    ).rejects.toThrow(IntentVkMismatchError);

    const notHex = [...intent.vkAsFields];
    notHex[0] = String(BigInt(notHex[0]));
    await expect(
      proveSwapSettle({ ...mb, intent: { ...intent, vkAsFields: notHex } }),
    ).rejects.toThrow(IntentVkMismatchError);

    expect(bbCalls()).toEqual([]);
  });

  it("passes the pinned intent to bb with a 0700 dir and 0600 witness, then removes both", async () => {
    const proof = await proveSwapSettle({ ...mb, intent });
    expect(proof.verified).toBe(true);
    expect(bbCalls()).toEqual(["--version", "prove", "700", "600", "verify"]);
    expect(readdirSync(scratch)).toEqual([]);
  });

  it("removes the witness when the native prove fails", async () => {
    process.env.FAKE_BB_MODE = "fail";
    const settle = proveSwapSettle({ ...mb, intent });
    await expect(settle).rejects.toThrow(ProofError);
    await expect(settle).rejects.toThrow(/Builder failure/);
    expect(readdirSync(scratch)).toEqual([]);
  });

  it("SIGTERM during the prove kills bb and removes the witness", async () => {
    process.env.FAKE_BB_MODE = "hang";
    const hostHandler = (): void => undefined;
    process.on("SIGTERM", hostHandler);
    try {
      const before = process.listeners("SIGTERM");
      const settle = proveSwapSettle({ ...mb, intent });
      const bbPid = await untilProveStarts();
      expect(readdirSync(scratch)).toHaveLength(1);

      const handler = newListener("SIGTERM", before);
      handler("SIGTERM");

      expect(readdirSync(scratch)).toEqual([]);
      await expect(settle).rejects.toThrow(ProofError);
      expect(isAlive(bbPid)).toBe(false);
      expect(process.listeners("SIGTERM")).not.toContain(handler);
    } finally {
      process.off("SIGTERM", hostHandler);
    }
  });

  it("re-raises SIGTERM when no host handler is installed", async () => {
    process.env.FAKE_BB_MODE = "hang";
    const others = process.listeners("SIGTERM");
    for (const l of others) process.off("SIGTERM", l);
    const kill = vi
      .spyOn(process, "kill")
      .mockImplementation((pid: number, signal?: string | number) => {
        if (pid === process.pid) return true;
        throw new Error(`unexpected kill(${pid}, ${String(signal)})`);
      });
    try {
      const settle = proveSwapSettle({ ...mb, intent });
      await untilProveStarts();
      const handler = newListener("SIGTERM", []);
      handler("SIGTERM");
      expect(kill).toHaveBeenCalledWith(process.pid, "SIGTERM");
      expect(readdirSync(scratch)).toEqual([]);
      await expect(settle).rejects.toThrow(ProofError);
    } finally {
      kill.mockRestore();
      for (const l of others) process.on("SIGTERM", l);
    }
  });

  it("the exit handler removes a live witness", async () => {
    process.env.FAKE_BB_MODE = "hang";
    const before = process.listeners("exit");
    const settle = proveSwapSettle({ ...mb, intent });
    await untilProveStarts();
    expect(readdirSync(scratch)).toHaveLength(1);

    newListener("exit", before)(0);

    expect(readdirSync(scratch)).toEqual([]);
    await expect(settle).rejects.toThrow(ProofError);
    expect(process.listeners("exit")).toEqual(before);
  });
});
