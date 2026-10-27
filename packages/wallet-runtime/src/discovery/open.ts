import { Fr } from "@aztec/foundation/fields";
import {
  commitmentPrefixMatches,
  computeNullifier,
  computePsi,
  demDecrypt,
  deriveCek,
  leaf as computeLeaf,
  NOTE_TYPE_STANDARD,
  recoverEvenY,
  reconstructCiphertext,
  RECORD_KIND_INCOMING,
  RECORD_KIND_SELF,
  unwrapCek,
  type CompleteComplianceHistory,
  type DerivedEph,
  type HowlNoteRecord,
  type Note,
} from "@hisoka/wallets";
import { WalletRuntimeError } from "../errors.js";
import type { VerifiedLeafSource } from "./ports.js";

export type LeafVerification = "verified" | "unverified";

/**
 * Compares an opened note with the verified tree leaf at its position before it may count toward a balance.
 * A prefix match and a clean decrypt do not prove the row is real: a phantom cell can carry both. Only the
 * leaf the tree was verified with does. `"unverified"` notes stay out of every spendable balance and out of
 * PSS until the spend path checks them against the on-chain root.
 */
export async function verifyAgainstTree(
  leaves: VerifiedLeafSource,
  leafIndex: number,
  commitment: Fr,
): Promise<LeafVerification> {
  const leaf = await leaves.leafAt(leafIndex);
  if (leaf === "unheld") return "unverified";
  if (!leaf.equals(commitment)) {
    throw new WalletRuntimeError(
      "LEAF_MISMATCH",
      `opened note commitment ${commitment.toString()} is not the verified tree leaf ${leaf.toString()} at index ${leafIndex}; the row is a phantom and is dropped`,
      {
        leafIndex: String(leafIndex),
        expected: leaf.toString(),
        actual: commitment.toString(),
      },
    );
  }
  return "verified";
}

/** How a tag that matched a row belongs to this wallet. */
export type OpenCandidate =
  | {
      readonly kind: "self";
      readonly eph: DerivedEph;
      readonly index: number;
      /** `Poseidon2(selfSpendPub)`: the owner a self note carries. */
      readonly ownerCommitment: Fr;
    }
  | {
      readonly kind: "incoming";
      readonly inKey: Fr;
      readonly index: number;
      /** `Poseidon2(in_pub_j)`: a received note is owned by the address it was sent to. */
      readonly ownerCommitment: Fr;
    };

export interface OpenedNote {
  readonly leafIndex: number;
  readonly commitment: Fr;
  readonly note: Note;
  readonly nullifier: Fr;
  readonly origin: "self" | "incoming";
  readonly derivationIndex: number;
  /** The epoch that opened a self note; null for an incoming note. */
  readonly complianceVersion: number | null;
}

export type OpenOutcome =
  | { readonly kind: "opened"; readonly note: OpenedNote }
  /** A self row under our tag that no epoch opens: never counted, always reported. */
  | { readonly kind: "unopenable"; readonly versionsTried: readonly number[] }
  /** Not this wallet's note: a probe miss, a coincidental prefix, or someone else's row. */
  | { readonly kind: "miss" };

const ADDRESS_LIMIT = 1n << 160n;

/**
 * Opens one discovery row with one candidate. A self row is tried under every compliance epoch, the one
 * covering `block` first, because a wrong key usually fails inside `leaf()` and that only means "try the
 * next epoch". Decrypting always "succeeds" here (ciphertext word 5 is rebuilt from the expected owner), so
 * a row is accepted only when the recomputed commitment matches: in full when the caller knows it
 * (self-index reads it from the log), by prefix otherwise.
 */
export async function openRecord(
  record: HowlNoteRecord,
  candidate: OpenCandidate,
  history: CompleteComplianceHistory,
  options: { readonly block?: number; readonly commitment?: Fr } = {},
): Promise<OpenOutcome> {
  if (candidate.kind === "self") {
    if (record.recordKind !== RECORD_KIND_SELF) return { kind: "miss" };
    const tried: number[] = [];
    for (const epoch of history.ring.candidatesFor(options.block)) {
      tried.push(epoch.version);
      let cek: Fr;
      try {
        cek = deriveCek(candidate.eph, epoch.pk);
      } catch {
        continue;
      }
      const opened = await tryOpen(record, cek, candidate, options.commitment);
      if (opened !== null) {
        return {
          kind: "opened",
          note: { ...opened, complianceVersion: epoch.version },
        };
      }
    }
    return { kind: "unopenable", versionsTried: tried };
  }

  if (record.recordKind !== RECORD_KIND_INCOMING) return { kind: "miss" };
  let cek: Fr;
  try {
    cek = await unwrapCek(
      record.cekWrap,
      candidate.inKey,
      recoverEvenY(record.ephemeralPkX.toBigInt()),
    );
  } catch {
    return { kind: "miss" };
  }
  const opened = await tryOpen(record, cek, candidate, options.commitment);
  return opened === null
    ? { kind: "miss" }
    : { kind: "opened", note: { ...opened, complianceVersion: null } };
}

async function tryOpen(
  record: HowlNoteRecord,
  cek: Fr,
  candidate: OpenCandidate,
  fullCommitment: Fr | undefined,
): Promise<Omit<OpenedNote, "complianceVersion"> | null> {
  let note: Note;
  let commitment: Fr;
  let psi: Fr;
  try {
    const ciphertext = await reconstructCiphertext(
      record,
      cek,
      candidate.ownerCommitment,
    );
    const plaintext = await demDecrypt(cek, ciphertext);
    psi = await computePsi(cek);
    note = {
      noteVersion: plaintext[0],
      assetId: plaintext[1],
      noteType: plaintext[2],
      conditionsHash: plaintext[3],
      value: plaintext[4].toBigInt(),
      owner: plaintext[5],
      psi,
      parents: plaintext[6],
    };
    commitment = await computeLeaf(note);
  } catch {
    return null;
  }
  const matches =
    fullCommitment === undefined
      ? commitmentPrefixMatches(record, commitment)
      : fullCommitment.equals(commitment);
  if (!matches) return null;
  if (
    note.noteType.toBigInt() !== NOTE_TYPE_STANDARD ||
    note.owner.isZero() ||
    !note.owner.equals(candidate.ownerCommitment) ||
    note.assetId.toBigInt() >= ADDRESS_LIMIT
  ) {
    return null;
  }
  return {
    leafIndex: record.leafIndex,
    commitment,
    note,
    nullifier: await computeNullifier(psi, new Fr(BigInt(record.leafIndex))),
    origin: candidate.kind,
    derivationIndex: candidate.index,
  };
}
