import { Fr } from "@aztec/foundation/fields";
import type { SelfMintAuthorization } from "../discovery/preflight.js";
import { consumeSelfMints } from "../discovery/preflight.js";
import { Point } from "@zk-kit/baby-jubjub";
import { toFr } from "../crypto/fields.js";
import { deriveCek } from "../crypto/kem.js";
import {
  assertBjjSubgroupPoint,
  derivePublicIncomingKey,
  pubkeyOwner,
  publicKey,
} from "../note/keys.js";
import {
  leaf as computeLeaf,
  Note,
  NOTE_TYPE_STANDARD,
  NOTE_VERSION,
} from "../note/note.js";
import { computePsi } from "../note/nullifier.js";
import type { SelfEphemeral } from "../repositories.js";
import type { CompleteComplianceHistory } from "../note/complianceKeys.js";
import {
  assertMemoAsset,
  assertMemoTimelock,
  assertMemoValue,
  PublicMemo,
  PublicMemoError,
  publicMemoId,
} from "./memo.js";

const ZERO = new Fr(0n);
const MAX_TIMESTAMP = (1n << 64n) - 1n;

/** The prover's `NoteInput` shape (value as a field, range-checked at its marshal boundary). Mirrored
 *  rather than imported: `@hisoka/prover` depends on this package, so importing it back would cycle. */
export interface ProverNoteInput {
  noteVersion: Fr;
  assetId: Fr;
  noteType: Fr;
  conditionsHash: Fr;
  value: Fr;
  owner: Fr;
  psi: Fr;
  parents: Fr;
}

/** Structurally the prover's `PublicClaimInputs`; pass straight to `provePublicClaim`. */
export interface PublicClaimWitness {
  memoId: Fr;
  compliancePk: Point<bigint>;
  currentTimestamp: number;

  val: Fr;
  assetId: Fr;
  timelock: Fr;
  ownerX: Fr;
  ownerY: Fr;
  salt: Fr;

  recipientSk: Fr;
  noteOut: ProverNoteInput;
  eph: Fr;
}

/** The key-repository capability a claim needs after its self ephemeral has been preflighted. */
export interface SelfNoteKeys {
  getSelfSpendPub(): Promise<Point<bigint>>;
}

export interface PublicClaimRequest {
  /** A `DiscoveredPublicMemo` from the scanner fits here. */
  memo: PublicMemo;
  viewKey: Fr;
  /** Index of the public receiving address the memo was posted to; re-derived and re-checked, never trusted. */
  ownerIndex: bigint;
  compliancePk: Point<bigint>;
  complianceVersion: number;
  complianceHistory: CompleteComplianceHistory;
  chainId: bigint;
  poolAddress: string;
  deploymentAnchor: bigint;
  keys: SelfNoteKeys;
  selfMint: SelfMintAuthorization;
  currentTimestamp?: number;
}

export interface AssembledPublicClaim {
  inputs: PublicClaimWitness;
  /** Plaintext note the claim mints, for the wallet's own bookkeeping. */
  note: Note;
  commitment: Fr;
  ephemeralIndex: number;
}

function assertClaimable(memo: PublicMemo, currentTimestamp: number): void {
  if (
    !Number.isSafeInteger(currentTimestamp) ||
    currentTimestamp < 0 ||
    BigInt(currentTimestamp) > MAX_TIMESTAMP
  ) {
    throw new PublicMemoError(
      `public claim currentTimestamp must be a non-negative u64 second count (got ${currentTimestamp}).`,
    );
  }
  if (memo.timelock !== 0n && BigInt(currentTimestamp) < memo.timelock) {
    throw new PublicMemoError(
      `public memo ${memo.memoId.toString()} is timelocked until ${memo.timelock} and cannot be claimed at ${currentTimestamp}; the circuit asserts current_timestamp >= timelock.`,
    );
  }
}

/** Turns a discovered memo plus the wallet's keys into a fully populated `provePublicClaim` witness. The
 *  minted note is a self note owned by the wallet's spend key, not by the memo's owner point: the owner
 *  point only authorizes the claim, it never becomes note ownership. */
export async function buildPublicClaim(
  request: PublicClaimRequest,
): Promise<AssembledPublicClaim> {
  const currentTimestamp =
    request.currentTimestamp ?? Math.floor(Date.now() / 1000);
  const { memo } = request;
  assertClaimable(memo, currentTimestamp);
  assertMemoValue(memo.value);
  assertMemoTimelock(memo.timelock);
  assertMemoAsset(memo.assetId);

  const recipientSk = await derivePublicIncomingKey(
    request.viewKey,
    request.ownerIndex,
  );
  const ownerPub = publicKey(recipientSk);
  assertBjjSubgroupPoint(
    ownerPub,
    `Public receiving key at index ${request.ownerIndex}`,
  );

  const recomputed = await publicMemoId(memo, ownerPub);
  if (!recomputed.equals(memo.memoId)) {
    throw new PublicMemoError(
      `public memo ${memo.memoId.toString()} is not addressed to public receiving index ${request.ownerIndex} (that index yields ${recomputed.toString()}); it belongs to another index or another wallet.`,
    );
  }

  const owner = await pubkeyOwner(await request.keys.getSelfSpendPub());
  const [selfMint] = consumeSelfMints([request.selfMint], {
    ownerCommitment: owner,
    compliancePk: request.compliancePk,
    complianceVersion: request.complianceVersion,
    complianceHistory: request.complianceHistory,
    chainId: request.chainId,
    poolAddress: request.poolAddress,
    deploymentAnchor: request.deploymentAnchor,
  });
  const eph = selfMint.eph as SelfEphemeral["eph"];
  const ephemeralIndex = selfMint.index;
  const cek = deriveCek(eph, request.compliancePk);
  const psi = await computePsi(cek);

  const note: Note = {
    noteVersion: NOTE_VERSION,
    assetId: memo.assetId,
    noteType: new Fr(NOTE_TYPE_STANDARD),
    conditionsHash: ZERO,
    value: memo.value,
    owner,
    psi,
    parents: ZERO,
  };
  const commitment = await computeLeaf(note);

  return {
    inputs: {
      memoId: memo.memoId,
      compliancePk: request.compliancePk,
      currentTimestamp,
      val: toFr(memo.value),
      assetId: memo.assetId,
      timelock: toFr(memo.timelock),
      ownerX: new Fr(ownerPub[0]),
      ownerY: new Fr(ownerPub[1]),
      salt: memo.salt,
      recipientSk,
      noteOut: {
        noteVersion: note.noteVersion,
        assetId: note.assetId,
        noteType: note.noteType,
        conditionsHash: note.conditionsHash,
        value: toFr(note.value),
        owner: note.owner,
        psi: note.psi,
        parents: note.parents,
      },
      eph,
    },
    note,
    commitment,
    ephemeralIndex,
  };
}
