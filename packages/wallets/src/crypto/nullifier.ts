import { Fr } from "@aztec/foundation/fields";
import { Point } from "@zk-kit/baby-jubjub";
import { Poseidon } from "./Poseidon.js";
import { toFr } from "./fields.js";

export async function deriveNullifier(
  nk: Fr,
  commitment: Fr,
  leaf_index: number | bigint,
): Promise<Fr> {
  return Poseidon.hash([nk, commitment, new Fr(BigInt(leaf_index))]);
}

export async function computeOwner(pk_spend: Point<bigint>): Promise<Fr> {
  return Poseidon.hash([toFr(pk_spend[0]), toFr(pk_spend[1])]);
}
