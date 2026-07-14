import { describe, it, expect } from "vitest";
import { Fr } from "@aztec/foundation/fields";
import { Point } from "@zk-kit/baby-jubjub";
import { deriveCek, computePsi } from "@hisoka/wallets";
import { proveSwapIntent } from "../provers/swapIntent.js";
import { SwapIntentInputs, NoteInput } from "../types.js";
import {
  INTENT_VK_HASH,
  INTENT_VK_LEN,
  INTENT_PROOF_LEN,
  INTENT_PI_LEN,
} from "../config.js";

// Fail-closed recursion-pin guard (CI-safe, bb.js only): swap_intent's compiled recursion vkHash + widths MUST
// equal the pinned INTENT_* constants baked into kage_lib and swap_settle. A swap_intent change that moves the VK
// without re-pinning fails here, before swap_settle silently rejects every real proof on-chain. Also pins TS<->Noir
// parity: the TS-built witness yields the nargo swap_intent KAT's golden nullifier + root.
const C: Point<bigint> = [
  0x085ed469c9a9f102b6d4f6f909b8ceaf6ca49b39759ac2e0feb7e0aada8b7111n,
  0x245e25ab2bd42f0280a5ade750828dd6868f5225ae798d6b51c676f519c8f4e8n,
];
const FROM_ASSET = 0x1234567890123456789012345678901234567890n;
const TO_ASSET = 0xabcdefabcdefabcdefabcdefabcdefabcdefabcdn;
const SELF_OWNER = new Fr(
  0x2874ae964d8b283e2f521a7f14125fc92747bb9770139b8d4b70ee09e2d83785n,
);
const A_IN_PSI = new Fr(
  0x0981a88f9e119b057498a4ab99ed5379a1ea91c642454fc0c07aacc1f5cd5731n,
);

function note(
  asset: bigint,
  value: bigint,
  psi: Fr,
  parents: bigint,
): NoteInput {
  return {
    noteVersion: new Fr(1n),
    assetId: new Fr(asset),
    noteType: new Fr(0n),
    conditionsHash: new Fr(0n),
    value: new Fr(value),
    owner: SELF_OWNER,
    psi,
    parents: new Fr(parents),
  };
}

describe("Kage recursion pin: vkHash + width parity", () => {
  it("swap_intent recursion vkHash + widths == pinned INTENT_* constants; TS<->Noir nullifier/root match", async () => {
    const changePsi = await computePsi(deriveCek(new Fr(9n), C));
    const receivedPsi = await computePsi(deriveCek(new Fr(15n), C));
    const inputs: SwapIntentInputs = {
      compliancePk: C,
      noteIn: note(FROM_ASSET, 100n, A_IN_PSI, 0n),
      spendScalar: new Fr(789n),
      indexIn: 0,
      pathIn: Array(32).fill(new Fr(0n)),
      changeNote: note(FROM_ASSET, 40n, changePsi, 0n),
      changeEph: new Fr(9n),
      receivedNote: note(TO_ASSET, 50n, receivedPsi, 0n),
      receivedEph: new Fr(15n),
      toAsset: new Fr(TO_ASSET),
      fromAmount: new Fr(60n),
      expiry: new Fr(2000000000n),
    };

    const r = await proveSwapIntent(inputs);

    expect(r.verified).toBe(true);
    expect(r.vkHash).toBe(INTENT_VK_HASH);
    expect(r.vkAsFields.length).toBe(INTENT_VK_LEN);
    expect(r.proofAsFields.length).toBe(INTENT_PROOF_LEN);
    expect(r.publicInputs.length).toBe(INTENT_PI_LEN);
    expect(BigInt(r.publicInputs[0])).toBe(
      0x2761654f0b4e9f47ac9bafe900c723ead042a888da718a34b6ecc8036850755en,
    );
    expect(BigInt(r.publicInputs[1])).toBe(
      0x09b087f618ba26b56f02ad1438a08cf9681445de37e85771c2e77f3058e0a551n,
    );
  }, 180000);
});
