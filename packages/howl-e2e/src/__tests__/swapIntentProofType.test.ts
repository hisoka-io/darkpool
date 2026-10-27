import { describe, expect, it } from "vitest";
import type { SwapIntentProof } from "@hisoka/prover";

// The prover package does not typecheck its own tests, so this pin lives where `tsc --noEmit` covers tests.
describe("SwapIntentProof typing", () => {
  it("admits only a verified intent proof", () => {
    const fields = {
      proof: new Uint8Array(0),
      proofAsFields: [],
      publicInputs: [],
      vkAsFields: [],
      vkHash: "0x00",
    };
    const verified: SwapIntentProof = { ...fields, verified: true };
    // @ts-expect-error an intent proof that failed local verification is never a SwapIntentProof
    const unverified: SwapIntentProof = { ...fields, verified: false };
    expect([verified.verified, unverified.verified]).toEqual([true, false]);
  });
});
