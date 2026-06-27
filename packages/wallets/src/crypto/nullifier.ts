import { Fr } from "@aztec/foundation/fields";
import { Poseidon } from "./Poseidon.js";

/** Path A (self-owned): N = Poseidon(nullifier_secret, commitment, leaf_index) */
export async function deriveNullifierPathA(
  note_nullifier_secret: Fr,
  commitment: Fr,
  leaf_index: number | bigint,
): Promise<Fr> {
  return Poseidon.hash([
    note_nullifier_secret,
    commitment,
    new Fr(BigInt(leaf_index)),
  ]);
}

/** Path B (received): N = Poseidon(shared_secret, commitment, leaf_index) */
export async function deriveNullifierPathB(
  shared_secret: Fr,
  commitment: Fr,
  leaf_index: number | bigint,
): Promise<Fr> {
  return Poseidon.hash([shared_secret, commitment, new Fr(BigInt(leaf_index))]);
}
