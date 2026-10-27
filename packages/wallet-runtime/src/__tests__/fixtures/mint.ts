import { Fr } from "@aztec/foundation/fields";
import type { Point } from "@zk-kit/baby-jubjub";
import {
  isEvenY,
  mintIncomingNote,
  publicKey,
  type DarkAccount,
  type MintedNote,
  type SentMemoNote,
} from "@hisoka/wallets";
import { mintSelfNote } from "@hisoka/wallets/unsafe-sim";

export const ASSET = new Fr(0x00000000000000000000000000000000000a55e7n);

/** The first self-ephemeral index at or after `from` whose public key has even y (a discoverable tag). */
export async function evenSelfIndex(
  account: DarkAccount,
  from: number,
): Promise<number> {
  for (let i = from; ; i++) {
    if (isEvenY(publicKey(await account.getSelfEphemeral(BigInt(i))))) return i;
  }
}

export async function evenIncomingIndex(
  account: DarkAccount,
  from: number,
): Promise<number> {
  for (let i = from; ; i++) {
    if (isEvenY(publicKey(await account.getIncomingKey(BigInt(i))))) return i;
  }
}

export async function selfNote(
  account: DarkAccount,
  index: number,
  value: bigint,
  compliancePk: Point<bigint>,
  asset = ASSET,
): Promise<MintedNote> {
  return mintSelfNote(
    await account.getSelfEphemeral(BigInt(index)),
    value,
    await account.getSelfSpendKey(),
    asset,
    compliancePk,
  );
}

/** A deterministic memo ephemeral with even-y public key, from `seed` upwards. */
export function memoEph(seed: bigint): Fr {
  for (let s = seed; ; s++) {
    const eph = new Fr(s);
    if (isEvenY(publicKey(eph))) return eph;
  }
}

export async function memoTo(
  recipient: DarkAccount,
  inIndex: number,
  value: bigint,
  compliancePk: Point<bigint>,
  seed: bigint,
): Promise<SentMemoNote> {
  const inPub = await recipient.getIncomingPub(BigInt(inIndex));
  const minted = await mintIncomingNote(
    memoEph(seed),
    value,
    inPub,
    await recipient.getIncomingKey(BigInt(inIndex)),
    ASSET,
    compliancePk,
  );
  if (minted.cekWrap === undefined) throw new Error("memo without a CEK wrap");
  return { ...minted, inPub, cekWrap: minted.cekWrap };
}
