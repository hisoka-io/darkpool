import { beforeEach, describe, expect, it, vi } from "vitest";
import { Fr } from "@aztec/foundation/fields";
import type { DerivedEph } from "@hisoka/wallets";
import type { NoteInput, SwapIntentInputs } from "../types.js";
import { INTENT_PI_LEN, INTENT_PROOF_LEN, INTENT_VK_LEN } from "../config.js";

const backend = vi.hoisted(() => ({
  verifies: true,
  proofFields: 0,
}));

vi.mock("@noir-lang/noir_js", () => ({
  Noir: class {
    execute() {
      return Promise.resolve({ witness: new Uint8Array([1]) });
    }
  },
}));

vi.mock("@aztec/bb.js", () => ({
  Barretenberg: {
    initSingleton: () => Promise.resolve(),
    getSingleton: () => ({}),
  },
  UltraHonkBackend: class {
    generateProof() {
      return Promise.resolve({
        proof: new Uint8Array(backend.proofFields * 32),
        publicInputs: Array.from({ length: INTENT_PI_LEN }, () => "0x01"),
      });
    }
    verifyProof() {
      return Promise.resolve(backend.verifies);
    }
    generateRecursiveProofArtifacts() {
      return Promise.resolve({
        vkAsFields: Array.from({ length: INTENT_VK_LEN }, () => "0x02"),
        vkHash: "0x03",
      });
    }
  },
}));

const { proveSwapIntent, UnverifiedIntentProofError } =
  await import("../provers/kage/swapIntent.js");
const { ProofError } = await import("../errors.js");

function note(): NoteInput {
  const one = new Fr(1n);
  return {
    noteVersion: one,
    assetId: one,
    noteType: Fr.ZERO,
    conditionsHash: Fr.ZERO,
    value: one,
    owner: one,
    psi: one,
    parents: Fr.ZERO,
  };
}

const INPUTS: SwapIntentInputs = {
  compliancePk: [1n, 2n],
  noteIn: note(),
  spendScalar: new Fr(1n),
  indexIn: 0,
  pathIn: Array.from({ length: 32 }, () => Fr.ZERO),
  changeNote: note(),
  changeEph: new Fr(9n) as DerivedEph,
  receivedNote: note(),
  receivedEph: new Fr(15n) as DerivedEph,
  toAsset: new Fr(2n),
  fromAmount: new Fr(1n),
  expiry: new Fr(1n),
};

describe("proveSwapIntent local verification", () => {
  beforeEach(() => {
    backend.verifies = true;
    backend.proofFields = INTENT_PROOF_LEN;
  });

  it("returns the recursion artifacts of a proof that verifies locally", async () => {
    const out = await proveSwapIntent(INPUTS);
    expect(out.verified).toBe(true);
    expect(out.proofAsFields).toHaveLength(INTENT_PROOF_LEN);
    expect(out.vkAsFields).toHaveLength(INTENT_VK_LEN);
  });

  it("throws a typed error, not a proof object, when local verification fails", async () => {
    backend.verifies = false;
    const attempt = proveSwapIntent(INPUTS);
    await expect(attempt).rejects.toBeInstanceOf(UnverifiedIntentProofError);
    await expect(attempt).rejects.toBeInstanceOf(ProofError);
    await expect(attempt).rejects.toMatchObject({
      name: "UnverifiedIntentProofError",
      circuit: "swap_intent",
      message: expect.stringMatching(/^proof failed for swap_intent: /),
    });
  });

  it("reports a width drift once, distinct from a verification failure", async () => {
    backend.proofFields = INTENT_PROOF_LEN - 1;
    const attempt = proveSwapIntent(INPUTS);
    await expect(attempt).rejects.toBeInstanceOf(ProofError);
    await expect(attempt).rejects.not.toBeInstanceOf(
      UnverifiedIntentProofError,
    );
    await expect(attempt).rejects.toMatchObject({
      message: `proof failed for swap_intent: recursion width drift: vk=${INTENT_VK_LEN} proof=${INTENT_PROOF_LEN - 1} pi=${INTENT_PI_LEN}`,
    });
  });
});
