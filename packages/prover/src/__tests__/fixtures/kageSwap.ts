import { Fr } from "@aztec/foundation/fields";
import { Point } from "@zk-kit/baby-jubjub";
import { deriveCek, computePsi, leaf, type DerivedEph } from "@hisoka/wallets";
import { SwapIntentInputs, SwapSettleInputs, NoteInput } from "../../types.js";

export const COMPLIANCE: Point<bigint> = [
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
const eph = (n: bigint): DerivedEph => new Fr(n) as DerivedEph;
const MAKER_IN = 100n;
/** The toAsset amount the honest intent asks for; `expected_return` is intent word 7. */
export const EXPECTED_RETURN = 50n;
export const EXPECTED_RETURN_WORD = 7;

async function psiOf(eph: bigint): Promise<Fr> {
  return computePsi(deriveCek(new Fr(eph), COMPLIANCE));
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

async function leafOf(asset: bigint, value: bigint, psi: Fr): Promise<Fr> {
  return leaf({
    noteVersion: new Fr(1n),
    assetId: new Fr(asset),
    noteType: new Fr(0n),
    conditionsHash: new Fr(0n),
    value,
    owner: OWNER,
    psi,
    parents: new Fr(0n),
  });
}

/** Taker A_in and maker B_in are the two leaves of a two-leaf tree; each is the other's only sibling. */
export async function swapFixture(): Promise<{
  intentInputs: SwapIntentInputs;
  maker: (paidToTaker: bigint) => Promise<Omit<SwapSettleInputs, "intent">>;
}> {
  const bInPsi = await psiOf(222n);
  const pathA = Array<Fr>(32).fill(Z);
  pathA[0] = await leafOf(TO_ASSET, MAKER_IN, bInPsi);
  const pathB = Array<Fr>(32).fill(Z);
  pathB[0] = await leafOf(FROM_ASSET, 100n, A_IN_PSI);

  const intentInputs: SwapIntentInputs = {
    compliancePk: COMPLIANCE,
    noteIn: proverNote(FROM_ASSET, 100n, A_IN_PSI, 0n),
    spendScalar: new Fr(789n),
    indexIn: 0,
    pathIn: pathA,
    changeNote: proverNote(FROM_ASSET, 40n, await psiOf(9n), 0n),
    changeEph: eph(9n),
    receivedNote: proverNote(TO_ASSET, EXPECTED_RETURN, await psiOf(15n), 0n),
    receivedEph: eph(15n),
    toAsset: new Fr(TO_ASSET),
    fromAmount: new Fr(60n),
    expiry: new Fr(2000000000n),
  };

  // The maker keeps B_in - paidToTaker as change, so a forged expected_return shrinks what he pays.
  const maker = async (
    paidToTaker: bigint,
  ): Promise<Omit<SwapSettleInputs, "intent">> => ({
    compliancePk: COMPLIANCE,
    currentTimestamp: new Fr(1000000000n),
    makerNoteIn: proverNote(TO_ASSET, MAKER_IN, bInPsi, 0n),
    makerSpendScalar: new Fr(789n),
    makerIndex: 1,
    makerPath: pathB,
    makerReceived: proverNote(FROM_ASSET, 60n, await psiOf(20n), 1n),
    makerReceivedEph: eph(20n),
    makerChange: proverNote(
      TO_ASSET,
      MAKER_IN - paidToTaker,
      await psiOf(28n),
      1n,
    ),
    makerChangeEph: eph(28n),
  });

  return { intentInputs, maker };
}
