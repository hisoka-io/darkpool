import { Fr } from "@aztec/foundation/fields";
import { Point } from "@zk-kit/baby-jubjub";
import { toFr } from "../crypto/fields.js";
import { calculatePublicMemoId } from "../crypto/index.js";

// DarkPool.publicTransfer bounds: value is the in-circuit u128, timelock is compared `as u64`.
const MAX_MEMO_VALUE = (1n << 128n) - 1n;
const MAX_MEMO_TIMELOCK = (1n << 64n) - 1n;
// asset ids are ERC20 addresses; anything at or above 2^160 cannot be a real asset.
const ASSET_MODULUS = 1n << 160n;

export class PublicMemoError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PublicMemoError";
  }
}

/** The escrow terms a `publicTransfer` commits to. `assetId` is the uint160 the contract folds into the
 *  memoId as `uint256(uint160(_asset))`. */
export interface PublicMemoTerms {
  assetId: Fr;
  value: bigint;
  timelock: bigint;
  salt: Fr;
}

/** A posted escrow: the terms plus the memoId DarkPool keys `isValidPublicMemo` by. A `DiscoveredPublicMemo`
 *  from the scanner satisfies this shape. */
export interface PublicMemo extends PublicMemoTerms {
  memoId: Fr;
}

export function assertMemoValue(value: bigint): void {
  if (value <= 0n) {
    throw new PublicMemoError(
      `publicTransfer value must be positive (got ${value}); DarkPool reverts ValueZero.`,
    );
  }
  if (value > MAX_MEMO_VALUE) {
    throw new PublicMemoError(
      `publicTransfer value ${value} exceeds the u128 note range (max ${MAX_MEMO_VALUE}); DarkPool reverts ValueTooLarge.`,
    );
  }
}

export function assertMemoTimelock(timelock: bigint): void {
  if (timelock < 0n) {
    throw new PublicMemoError(
      `publicTransfer timelock must not be negative (got ${timelock}); use 0 for an immediately claimable memo.`,
    );
  }
  if (timelock > MAX_MEMO_TIMELOCK) {
    throw new PublicMemoError(
      `publicTransfer timelock ${timelock} exceeds u64 (max ${MAX_MEMO_TIMELOCK}); DarkPool reverts TimelockTooLarge.`,
    );
  }
}

export function assertMemoAsset(assetId: Fr): void {
  const id = assetId.toBigInt();
  if (id === 0n) {
    throw new PublicMemoError(
      "publicTransfer asset is the zero address; the memo would escrow nothing and the transfer reverts.",
    );
  }
  if (id >= ASSET_MODULUS) {
    throw new PublicMemoError(
      `publicTransfer asset id ${id} is not a 20-byte ERC20 address; the claim circuit rejects it.`,
    );
  }
}

/** memoId = Poseidon2(value, asset, timelock, ownerX, ownerY, salt), byte-identical to DarkPool and the
 *  public_claim circuit. Field ORDER here differs from the publicTransfer calldata order. */
export function publicMemoId(
  terms: PublicMemoTerms,
  ownerPub: Point<bigint>,
): Promise<Fr> {
  return calculatePublicMemoId(
    toFr(terms.value),
    terms.assetId,
    toFr(terms.timelock),
    new Fr(ownerPub[0]),
    new Fr(ownerPub[1]),
    terms.salt,
  );
}
