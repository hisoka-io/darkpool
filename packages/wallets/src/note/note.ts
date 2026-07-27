import { Fr } from "@aztec/foundation/fields";
import { Poseidon } from "../crypto/Poseidon.js";

const U32_MAX = 0xffffffffn;
const TWO_POW_32 = 1n << 32n;
const TWO_POW_64 = 1n << 64n;
const TWO_POW_128 = 1n << 128n;

/** Frozen with the leaf preimage; MUST match the Noir globals of the same names (CONDITIONAL=2 reserved). */
export const NOTE_VERSION = new Fr(1n);
export const NOTE_TYPE_STANDARD = 0n;
export const NOTE_TYPE_MULTISIG = 1n;

export interface Parent {
  leafIndex: number;
}

/** Ordered STABLE-FIRST; matches Noir `Note`. `value` is u128. */
export interface Note {
  noteVersion: Fr;
  assetId: Fr;
  noteType: Fr;
  conditionsHash: Fr;
  value: bigint;
  owner: Fr;
  psi: Fr;
  parents: Fr;
}

/** Plaintext-commit over all 8 fields; byte-identical to Noir `Note::leaf`. */
export async function leaf(note: Note): Promise<Fr> {
  if (note.value < 0n || note.value >= TWO_POW_128) {
    throw new Error(`note value out of u128 range: ${note.value}`);
  }
  return Poseidon.hash([
    note.noteVersion,
    note.assetId,
    note.noteType,
    note.conditionsHash,
    new Fr(note.value),
    note.owner,
    note.psi,
    note.parents,
  ]);
}

function assertU32(name: string, value: number): bigint {
  if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) {
    throw new Error(`${name} not a u32 (0 <= x < 2^32): ${value}`);
  }
  return BigInt(value);
}

export function packParents(parents: [Parent, Parent]): Fr {
  const index0 = assertU32("leafIndex", parents[0].leafIndex);
  const index1 = assertU32("leafIndex", parents[1].leafIndex);
  return new Fr(index0 + index1 * TWO_POW_32);
}

// BN254_Fr - 1: >= 2^64, so unpackParents rejects it as a real index pack. Matches Noir `shared::note::PARENTS_HIDDEN`.
export const PARENTS_HIDDEN = new Fr(
  21888242871839275222246405745257275088548364400416034343698204186575808495617n -
    1n,
);

export function unpackParents(packed: Fr): [Parent, Parent] {
  const value = packed.toBigInt();
  if (value >= TWO_POW_64) {
    throw new Error("packed parents exceeds 2^64");
  }
  return [
    { leafIndex: Number(value & U32_MAX) },
    { leafIndex: Number((value >> 32n) & U32_MAX) },
  ];
}
