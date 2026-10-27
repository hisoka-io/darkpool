import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { UltraHonkBackend } from "@aztec/bb.js";
import { CompiledCircuit, Noir } from "@noir-lang/noir_js";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Buffer } from "node:buffer";
import { proveSwapIntent } from "../provers/kage/swapIntent.js";
import {
  IntentVkMismatchError,
  proveSwapSettle,
  nativeBbAvailable,
} from "../provers/kage/swapSettle.js";
import { proveSwapSettleNative } from "../provers/kage/settleNative.js";
import { ensureBBInitialized } from "../prover-base.js";
import { ProofError } from "../errors.js";
import {
  INTENT_PI_LEN,
  INTENT_PROOF_LEN,
  INTENT_VK_HASH,
  INTENT_VK_LEN,
} from "../config.js";
import { SwapIntentProof, SwapSettleInputs } from "../types.js";
import {
  EXPECTED_RETURN,
  EXPECTED_RETURN_WORD,
  swapFixture,
} from "./fixtures/kageSwap.js";

// Native-bb only, opt-in via `pnpm test:native`; skips loudly, never silently passes.
const OPT_IN = process.env.KAGE_NATIVE === "1";
const runnable = OPT_IN && nativeBbAvailable();
if (OPT_IN && !runnable) {
  console.warn(
    "[kage native gate] KAGE_NATIVE=1 but native bb unavailable -- skipping (not passing).",
  );
} else if (!OPT_IN) {
  console.warn(
    "[kage native gate] opt-in only; run `pnpm test:native` (needs native bb). Skipping.",
  );
}

const FORGER_DIR = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "../../test-harness/kage-intent-forger",
);
const NARGO = process.env.NARGO_PATH ?? "nargo";
const RECURSIVE = { verifierTarget: "noir-recursive" } as const;
const NATIVE_TIMEOUT_MS = 600_000;

const flip = (arr: string[], i: number): string[] => {
  const c = [...arr];
  c[i] = c[i].endsWith("0") ? c[i].slice(0, -1) + "1" : c[i].slice(0, -1) + "0";
  return c;
};
const word = (n: bigint): string => "0x" + n.toString(16).padStart(64, "0");

/** Proves the forger crate over `intentWords`, exactly as a taker would prove swap_intent. */
async function forgeIntent(intentWords: string[]): Promise<SwapIntentProof> {
  const target = mkdtempSync(join(tmpdir(), "kage-forger-target-"));
  try {
    execFileSync(
      NARGO,
      ["compile", "--program-dir", FORGER_DIR, "--target-dir", target],
      { stdio: "pipe" },
    );
    const forger = JSON.parse(
      readFileSync(join(target, "kage_intent_forger.json"), "utf8"),
    ) as CompiledCircuit;
    const backend = new UltraHonkBackend(
      forger.bytecode,
      await ensureBBInitialized(),
    );
    const { witness } = await new Noir(forger).execute({
      intent: intentWords,
    });
    const { proof, publicInputs } = await backend.generateProof(
      witness,
      RECURSIVE,
    );
    expect(await backend.verifyProof({ proof, publicInputs }, RECURSIVE)).toBe(
      true,
    );
    const art = await backend.generateRecursiveProofArtifacts(
      proof,
      publicInputs.length,
      RECURSIVE,
    );
    const proofAsFields: string[] = [];
    for (let i = 0; i < proof.length; i += 32) {
      proofAsFields.push(
        "0x" + Buffer.from(proof.slice(i, i + 32)).toString("hex"),
      );
    }
    return {
      proof,
      proofAsFields,
      publicInputs,
      vkAsFields: art.vkAsFields,
      vkHash: art.vkHash,
      verified: true,
    };
  } finally {
    rmSync(target, { recursive: true, force: true });
  }
}

(runnable ? describe : describe.skip)(
  "Kage recursion VK-pin adversarial gate (native bb)",
  () => {
    let intent: SwapIntentProof;
    let maker: (
      paidToTaker: bigint,
    ) => Promise<Omit<SwapSettleInputs, "intent">>;
    let scratch: string;
    const savedTmp = process.env.TMPDIR;

    beforeAll(async () => {
      const fixture = await swapFixture();
      intent = await proveSwapIntent(fixture.intentInputs);
      maker = fixture.maker;
      // The settle prover's secret scratch lands here, so each case can check nothing was left behind.
      scratch = mkdtempSync(join(tmpdir(), "kage-native-scratch-"));
      process.env.TMPDIR = scratch;
    }, NATIVE_TIMEOUT_MS);

    afterAll(() => {
      if (savedTmp === undefined) delete process.env.TMPDIR;
      else process.env.TMPDIR = savedTmp;
      if (scratch) rmSync(scratch, { recursive: true, force: true });
    });

    it(
      "happy accepts and leaves no witness; tampered VK / proof / PI all reject",
      async () => {
        const mb = await maker(EXPECTED_RETURN);
        const happy = await proveSwapSettle({ ...mb, intent });
        expect(happy.verified).toBe(true);
        expect(happy.publicInputs.length).toBe(42);
        expect(readdirSync(scratch)).toEqual([]);

        await expect(
          proveSwapSettle({
            ...mb,
            intent: { ...intent, vkAsFields: flip(intent.vkAsFields, 10) },
          }),
        ).rejects.toThrow(IntentVkMismatchError);
        await expect(
          proveSwapSettleNative({
            ...mb,
            intent: { ...intent, vkAsFields: flip(intent.vkAsFields, 10) },
          }),
        ).rejects.toThrow(ProofError);
        await expect(
          proveSwapSettle({
            ...mb,
            intent: {
              ...intent,
              proofAsFields: flip(intent.proofAsFields, 100),
            },
          }),
        ).rejects.toThrow(ProofError);
        await expect(
          proveSwapSettle({
            ...mb,
            intent: { ...intent, publicInputs: flip(intent.publicInputs, 11) },
          }),
        ).rejects.toThrow(ProofError);
        expect(readdirSync(scratch)).toEqual([]);
      },
      NATIVE_TIMEOUT_MS,
    );

    it(
      "a valid proof of another circuit with swap_intent's shape is rejected by the VK-hash pin",
      async () => {
        // The forged intent asks for 1 unit of toAsset while the relayed taker note still commits to 50.
        const forgedWords = [...intent.publicInputs];
        forgedWords[EXPECTED_RETURN_WORD] = word(1n);
        const forged = await forgeIntent(forgedWords);

        expect(forged.vkAsFields.length).toBe(INTENT_VK_LEN);
        expect(forged.proofAsFields.length).toBe(INTENT_PROOF_LEN);
        expect(forged.publicInputs.length).toBe(INTENT_PI_LEN);
        expect(forged.publicInputs).toEqual(forgedWords);
        expect(BigInt(forged.vkHash)).not.toBe(BigInt(INTENT_VK_HASH));

        const mb = await maker(1n);
        const settle = proveSwapSettleNative({ ...mb, intent: forged });
        await expect(settle).rejects.toThrow(ProofError);
        await expect(settle).rejects.toThrow(
          /native verify rejected the settle proof; bb prove reported: .*Recursive Ultra Verifier: VK Hash Mismatch/,
        );
        expect(readdirSync(scratch)).toEqual([]);

        await expect(
          proveSwapSettle({ ...mb, intent: forged }),
        ).rejects.toThrow(IntentVkMismatchError);
      },
      NATIVE_TIMEOUT_MS,
    );
  },
);
