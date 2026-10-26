import { Fr } from "@aztec/foundation/fields";
import { Point } from "@zk-kit/baby-jubjub";
import type { DerivedEph } from "../types/ephemeral.js";
import { deriveCek, wrapCek } from "../crypto/kem.js";
import { toFr } from "../crypto/fields.js";
import { BJJ_SUBGROUP_ORDER } from "../crypto/constants.js";
import { computePsi } from "./nullifier.js";
import {
  assertBjjSubgroupPoint,
  isEvenY,
  publicKey,
  pubkeyOwner,
} from "./keys.js";
import { leaf, NOTE_TYPE_STANDARD, NOTE_VERSION, type Note } from "./note.js";
import type { ProverNoteInput } from "../public/publicClaim.js";

const ZERO = toFr(0n);

/** A minted note plus everything a caller needs to prove it, log it, or find it again. */
export interface MintedNote {
  /** Structurally the prover's `NoteInput`; pass straight to a prove* call. */
  readonly note: ProverNoteInput;
  readonly commitment: Fr;
  readonly eph: DerivedEph;
  readonly ephPub: Point<bigint>;
  readonly cek: Fr;
  readonly psi: Fr;
  readonly spendScalar: Fr;
  /** Discovery tag. Self notes: the ephemeral's own public x. Incoming: the recipient's key. */
  readonly tag: Fr;
  readonly inPub?: Point<bigint>;
  readonly cekWrap?: Fr;
}

/** A memo as its SENDER holds it: the recipient's opening key is the one field a sender cannot know. */
export interface SentMemoNote extends Omit<MintedNote, "spendScalar"> {
  readonly inPub: Point<bigint>;
  readonly cekWrap: Fr;
}

async function finish(
  eph: Fr,
  value: bigint,
  owner: Fr,
  assetId: Fr,
  parents: Fr,
  compliancePk: Point<bigint>,
): Promise<Omit<MintedNote, "spendScalar" | "eph">> {
  const cek = deriveCek(eph, compliancePk);
  const psi = await computePsi(cek);
  const plaintext: Note = {
    noteVersion: NOTE_VERSION,
    assetId,
    noteType: toFr(NOTE_TYPE_STANDARD),
    conditionsHash: ZERO,
    value,
    owner,
    psi,
    parents,
  };
  const commitment = await leaf(plaintext);
  const ephPub = publicKey(eph);
  return {
    note: {
      noteVersion: NOTE_VERSION,
      assetId,
      noteType: toFr(NOTE_TYPE_STANDARD),
      conditionsHash: ZERO,
      value: toFr(value),
      owner,
      psi,
      parents,
    },
    commitment,
    ephPub,
    cek,
    psi,
    tag: new Fr(ephPub[0]),
  };
}

/**
 * A note owned by the spender themselves: a deposit, a change output, or a split output.
 *
 * `eph` MUST be `DerivedEph`, reserved from the durable counter. The discovery tag for a self note IS the
 * ephemeral's own public x and the scalar never travels, so a sampled ephemeral yields a note whose owner
 * can never re-derive the tag and never find it again.
 */
export async function mintSelfNote(
  eph: DerivedEph,
  value: bigint,
  spendScalar: Fr,
  assetId: Fr,
  compliancePk: Point<bigint>,
  parents: Fr = ZERO,
): Promise<MintedNote> {
  const owner = await pubkeyOwner(publicKey(spendScalar));
  return {
    ...(await finish(eph, value, owner, assetId, parents, compliancePk)),
    eph,
    spendScalar,
  };
}

export class MemoMintError extends Error {
  constructor(
    readonly reason:
      | "MEMO_EPH_RANGE"
      | "MEMO_EPH_ODD_Y"
      | "RECIPIENT_KEY_INVALID"
      | "RECIPIENT_KEY_ODD_Y",
    message: string,
  ) {
    super(message);
    this.name = "MemoMintError";
  }
}

/**
 * The memo checks `mint_incoming_note` asserts in-circuit, run before any work so a bad memo fails here with
 * a typed error instead of inside proving. Messages never carry the ephemeral: it opens the note.
 */
export function assertMemoInputs(eph: Fr, inPub: Point<bigint>): void {
  const scalar = eph.toBigInt();
  if (scalar === 0n || scalar >= BJJ_SUBGROUP_ORDER) {
    throw new MemoMintError(
      "MEMO_EPH_RANGE",
      "memo ephemeral must be a non-zero scalar below the BabyJubJub subgroup order",
    );
  }
  if (!isEvenY(publicKey(eph))) {
    throw new MemoMintError(
      "MEMO_EPH_ODD_Y",
      "memo ephemeral public key has odd y; only eph_pub.x is published, so sample another ephemeral",
    );
  }
  try {
    assertBjjSubgroupPoint(inPub, "Recipient incoming key");
  } catch (e) {
    throw new MemoMintError(
      "RECIPIENT_KEY_INVALID",
      e instanceof Error ? e.message : String(e),
    );
  }
  if (!isEvenY(inPub)) {
    throw new MemoMintError(
      "RECIPIENT_KEY_ODD_Y",
      "Recipient incoming key has odd y; its x is the discovery tag, so it is not a canonical address",
    );
  }
}

/**
 * A note paid to someone else's incoming address.
 *
 * `eph` is a bare `Fr` on purpose: a memo ephemeral is legitimately random, because `cek_wrap` travels and
 * the tag is the RECIPIENT's key rather than the ephemeral's. It must be in `[1, subgroup order)` with an
 * even-y public key, and `inPub` a non-identity, even-y subgroup point; anything else throws
 * `MemoMintError`. The PARAMETER types keep the two ephemeral families apart (`mintSelfNote` demands a
 * `DerivedEph`); the returned `eph` field is typed `DerivedEph` only because the result shares `MintedNote`,
 * so it is a sampled scalar and must never be passed to a self-note sink.
 */
export async function mintIncomingNote(
  eph: Fr,
  value: bigint,
  inPub: Point<bigint>,
  inKey: Fr,
  assetId: Fr,
  compliancePk: Point<bigint>,
  parents: Fr = ZERO,
): Promise<MintedNote> {
  return {
    ...(await mintMemoNote(eph, value, inPub, assetId, compliancePk, parents)),
    spendScalar: inKey,
  };
}

/**
 * `mintIncomingNote` for the sender, who holds the recipient's public key and nothing behind it. Same input
 * rules; `SentMemoNote.eph` is the sampled memo ephemeral, never a derived one.
 */
export async function mintMemoNote(
  eph: Fr,
  value: bigint,
  inPub: Point<bigint>,
  assetId: Fr,
  compliancePk: Point<bigint>,
  parents: Fr = ZERO,
): Promise<SentMemoNote> {
  assertMemoInputs(eph, inPub);
  const owner = await pubkeyOwner(inPub);
  const built = await finish(eph, value, owner, assetId, parents, compliancePk);
  return {
    ...built,
    // Branded only to fit the shared MintedNote shape; see mintIncomingNote.
    eph: eph as DerivedEph,
    inPub,
    cekWrap: await wrapCek(built.cek, eph, inPub),
    tag: new Fr(inPub[0]),
  };
}
