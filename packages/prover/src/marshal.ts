import { Fr } from "@aztec/foundation/fields";
import { Point } from "@zk-kit/baby-jubjub";
import { NOTE_TYPE_MULTISIG } from "@hisoka/wallets/frost";
import { NoteInput } from "./types.js";
import { ProofInputError } from "./errors.js";

const U128_MAX = (1n << 128n) - 1n;

export function pointHex(p: Point<bigint>): { x: string; y: string } {
  return { x: `0x${p[0].toString(16)}`, y: `0x${p[1].toString(16)}` };
}

// The circuit enforces the same (spend, view) <-> note_type biconditional; a mismatch builds an unspendable leaf.
export function memoRecipientPoints(
  circuit: string,
  memoNoteType: Fr,
  inPub?: Point<bigint>,
  multisig?: { gpk: Point<bigint>; viewPub: Point<bigint> },
): { spend: Point<bigint>; view: Point<bigint> } {
  const wantsMultisig = memoNoteType.toBigInt() === NOTE_TYPE_MULTISIG;
  if (multisig !== undefined) {
    if (inPub !== undefined) {
      throw new ProofInputError(
        circuit,
        "memo recipient: pass recipientInPub or recipientMultisig, never both",
      );
    }
    if (!wantsMultisig) {
      throw new ProofInputError(
        circuit,
        "memo recipient: recipientMultisig requires the memo note_type to be MULTISIG",
      );
    }
    if (multisig.gpk[0] === multisig.viewPub[0]) {
      throw new ProofInputError(
        circuit,
        "memo recipient: recipientMultisig gpk and viewPub must not share x, a MULTISIG memo decouples spend from view",
      );
    }
    return { spend: multisig.gpk, view: multisig.viewPub };
  }
  if (inPub === undefined) {
    throw new ProofInputError(
      circuit,
      "memo recipient: recipientInPub or recipientMultisig is required",
    );
  }
  if (wantsMultisig) {
    throw new ProofInputError(
      circuit,
      "memo recipient: a MULTISIG memo requires recipientMultisig (owner and view must decouple)",
    );
  }
  return { spend: inPub, view: inPub };
}

export function marshalU128(circuit: string, field: string, value: Fr): string {
  if (value.toBigInt() > U128_MAX) {
    throw new ProofInputError(circuit, `${field} exceeds u128 range`);
  }
  return value.toString();
}

export function marshalNote(
  circuit: string,
  note: NoteInput,
): Record<string, string> {
  if (note.value.toBigInt() > U128_MAX) {
    throw new ProofInputError(circuit, "note value exceeds u128 range");
  }
  return {
    note_version: note.noteVersion.toString(),
    asset_id: note.assetId.toString(),
    note_type: note.noteType.toString(),
    conditions_hash: note.conditionsHash.toString(),
    value: note.value.toString(),
    owner: note.owner.toString(),
    psi: note.psi.toString(),
    parents: note.parents.toString(),
  };
}
