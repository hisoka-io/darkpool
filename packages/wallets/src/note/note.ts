import { Fr } from "@aztec/foundation/fields";
import { Poseidon } from "../crypto/Poseidon.js";

const U32_MAX = 0xffffffffn;
const TWO_POW_64 = 1n << 64n;
const TWO_POW_128 = 1n << 128n;

/** One consumed input in the lineage list: (treeNum, leafIndex), each a u32. */
export interface Parent {
  treeNum: number;
  leafIndex: number;
}

/** Committed note plaintext, ordered STABLE-FIRST (matches Noir `Note`). `value` is u128. */
export interface NoteV2 {
  noteVersion: Fr;
  assetId: Fr;
  noteType: Fr;
  conditionsHash: Fr;
  value: bigint;
  owner: Fr;
  psi: Fr;
  parents: Fr;
}

/** PLAINTEXT-commit leaf over all 8 fields; psi is one of the 8, not appended. Byte-identical to Noir `Note::leaf`. */
export async function leaf(note: NoteV2): Promise<Fr> {
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

function packPair(p: Parent): bigint {
  const treeNum = assertU32("treeNum", p.treeNum);
  const leafIndex = assertU32("leafIndex", p.leafIndex);
  return (treeNum << 32n) + leafIndex;
}

/** Pack up to 2 parents: pair0 in bits 0..63, pair1 in bits 64..127. Deposit = [{0,0},{0,0}] -> 0. */
export function packParents(parents: [Parent, Parent]): Fr {
  return new Fr(packPair(parents[0]) + packPair(parents[1]) * TWO_POW_64);
}

function unpackPair(pair: bigint): Parent {
  return {
    treeNum: Number((pair >> 32n) & U32_MAX),
    leafIndex: Number(pair & U32_MAX),
  };
}

export function unpackParents(packed: Fr): [Parent, Parent] {
  const value = packed.toBigInt();
  if (value >= TWO_POW_128) {
    throw new Error("packed parents exceeds 2^128");
  }
  return [
    unpackPair(value & (TWO_POW_64 - 1n)),
    unpackPair((value >> 64n) & (TWO_POW_64 - 1n)),
  ];
}
