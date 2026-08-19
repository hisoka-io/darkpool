import { Fr } from "@aztec/foundation/fields";
import { Point } from "@zk-kit/baby-jubjub";
import type { DerivedEph } from "../types/ephemeral.js";
import { deriveCek, wrapCek } from "../crypto/kem.js";
import { toFr } from "../crypto/fields.js";
import { computePsi } from "./nullifier.js";
import { publicKey, pubkeyOwner } from "./keys.js";
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

async function finish(
  eph: DerivedEph,
  value: bigint,
  owner: Fr,
  assetId: Fr,
  spendScalar: Fr,
  parents: Fr,
  compliancePk: Point<bigint>,
): Promise<MintedNote> {
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
    eph,
    ephPub,
    cek,
    psi,
    spendScalar,
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
  return finish(eph, value, owner, assetId, spendScalar, parents, compliancePk);
}

/**
 * A note paid to someone else's incoming address.
 *
 * `eph` is a bare `Fr` on purpose: a memo ephemeral is legitimately random, because `cek_wrap` travels and
 * the tag is the RECIPIENT's key rather than the ephemeral's. Conflating the two families is what produced
 * the undiscoverable-note defect, so the type system keeps them apart.
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
  const owner = await pubkeyOwner(inPub);
  const built = await finish(
    eph as DerivedEph,
    value,
    owner,
    assetId,
    inKey,
    parents,
    compliancePk,
  );
  return {
    ...built,
    inPub,
    cekWrap: await wrapCek(built.cek, eph, inPub),
    tag: new Fr(inPub[0]),
  };
}
