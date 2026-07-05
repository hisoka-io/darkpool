import { Point } from "@zk-kit/baby-jubjub";
import { NoteInput } from "./types.js";
import { ProofInputError } from "./errors.js";

const U128_MAX = (1n << 128n) - 1n;

export function pointHex(p: Point<bigint>): { x: string; y: string } {
  return { x: `0x${p[0].toString(16)}`, y: `0x${p[1].toString(16)}` };
}

// value range-checked to u128: the in-circuit field is u128 and overflow aborts witness generation.
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
