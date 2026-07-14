import { describe, it, expect } from "vitest";
import { Fr } from "@aztec/foundation/fields";
import { Point } from "@zk-kit/baby-jubjub";
import { deriveCek, computePsi, leaf } from "@hisoka/wallets";
import { proveSwapIntent } from "../provers/swapIntent.js";
import { proveSwapSettle, nativeBbAvailable } from "../provers/swapSettle.js";
import { SwapIntentInputs, SwapSettleInputs, NoteInput } from "../types.js";

// The VK-pin adversarial gate: swap_settle accepts ONLY the pinned swap_intent VK. Native-bb only (the outer
// recursion is excluded from bb.js), so it is opt-in via `pnpm test:native` and skips with a clear log otherwise --
// it never silently passes. Happy path ACCEPTS; a tampered VK / proof / public inputs each REJECT.
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

const C: Point<bigint> = [
  0x085ed469c9a9f102b6d4f6f909b8ceaf6ca49b39759ac2e0feb7e0aada8b7111n,
  0x245e25ab2bd42f0280a5ade750828dd6868f5225ae798d6b51c676f519c8f4e8n,
];
const FROM_ASSET = 0x1234567890123456789012345678901234567890n;
const TO_ASSET = 0xabcdefabcdefabcdefabcdefabcdefabcdefabcdn;
const OWNER = new Fr(
  0x2874ae964d8b283e2f521a7f14125fc92747bb9770139b8d4b70ee09e2d83785n,
);
const A_IN_PSI = new Fr(
  0x0981a88f9e119b057498a4ab99ed5379a1ea91c642454fc0c07aacc1f5cd5731n,
);
const Z = new Fr(0n);

async function psiOf(eph: bigint): Promise<Fr> {
  return computePsi(deriveCek(new Fr(eph), C));
}
function proverNote(
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
    owner: OWNER,
    psi,
    parents: new Fr(parents),
  };
}
async function leafOf(
  asset: bigint,
  value: bigint,
  psi: Fr,
  parents: bigint,
): Promise<Fr> {
  return leaf({
    noteVersion: new Fr(1n),
    assetId: new Fr(asset),
    noteType: new Fr(0n),
    conditionsHash: new Fr(0n),
    value,
    owner: OWNER,
    psi,
    parents: new Fr(parents),
  });
}
const flip = (arr: string[], i: number): string[] => {
  const c = [...arr];
  c[i] = c[i].endsWith("0") ? c[i].slice(0, -1) + "1" : c[i].slice(0, -1) + "0";
  return c;
};

(runnable ? describe : describe.skip)(
  "Kage recursion VK-pin adversarial gate (native bb)",
  () => {
    it("happy accepts; tampered VK / proof / PI all reject", async () => {
      const bInPsi = await psiOf(222n);
      const leafA = await leafOf(FROM_ASSET, 100n, A_IN_PSI, 0n);
      const leafB = await leafOf(TO_ASSET, 100n, bInPsi, 0n);
      const pathA = Array<Fr>(32).fill(Z);
      pathA[0] = leafB;
      const pathB = Array<Fr>(32).fill(Z);
      pathB[0] = leafA;

      const intentInputs: SwapIntentInputs = {
        compliancePk: C,
        noteIn: proverNote(FROM_ASSET, 100n, A_IN_PSI, 0n),
        spendScalar: new Fr(789n),
        indexIn: 0,
        pathIn: pathA,
        changeNote: proverNote(FROM_ASSET, 40n, await psiOf(9n), 0n),
        changeEph: new Fr(9n),
        receivedNote: proverNote(TO_ASSET, 50n, await psiOf(15n), 0n),
        receivedEph: new Fr(15n),
        toAsset: new Fr(TO_ASSET),
        fromAmount: new Fr(60n),
        expiry: new Fr(2000000000n),
      };
      const intent = await proveSwapIntent(intentInputs);

      const makerBase = (): Omit<SwapSettleInputs, "intent"> => ({
        compliancePk: C,
        currentTimestamp: new Fr(1000000000n),
        makerNoteIn: proverNote(TO_ASSET, 100n, bInPsi, 0n),
        makerSpendScalar: new Fr(789n),
        makerIndex: 1,
        makerPath: pathB,
        makerReceived: proverNote(FROM_ASSET, 60n, Z, 1n),
        makerReceivedEph: new Fr(20n),
        makerChange: proverNote(TO_ASSET, 50n, Z, 1n),
        makerChangeEph: new Fr(28n),
      });
      // maker self-note psi is CEK-derived from the maker's eph, matching mint_self_note.
      const mb = makerBase();
      mb.makerReceived.psi = await psiOf(20n);
      mb.makerChange.psi = await psiOf(28n);

      const happy = await proveSwapSettle({ ...mb, intent });
      expect(happy.verified).toBe(true);
      expect(happy.publicInputs.length).toBe(42);

      await expect(
        proveSwapSettle({
          ...mb,
          intent: { ...intent, vkAsFields: flip(intent.vkAsFields, 10) },
        }),
      ).rejects.toThrow();
      await expect(
        proveSwapSettle({
          ...mb,
          intent: { ...intent, proofAsFields: flip(intent.proofAsFields, 100) },
        }),
      ).rejects.toThrow();
      await expect(
        proveSwapSettle({
          ...mb,
          intent: { ...intent, publicInputs: flip(intent.publicInputs, 11) },
        }),
      ).rejects.toThrow();
    }, 600000);
  },
);
