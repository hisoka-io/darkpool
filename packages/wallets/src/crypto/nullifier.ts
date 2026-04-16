import { Fr } from "@aztec/foundation/fields";
import { Poseidon } from "./Poseidon.js";

/** Path A (self-owned): N = Poseidon(nullifier_secret) */
export async function deriveNullifierPathA(
  note_nullifier_secret: Fr,
): Promise<Fr> {
  return Poseidon.hashScalar(note_nullifier_secret);
}

/** Path B (received): N = Poseidon(shared_secret, commitment, leaf_index) */
export async function deriveNullifierPathB(
  shared_secret: Fr,
  commitment: Fr,
  leaf_index: number | bigint,
): Promise<Fr> {
  return Poseidon.hash([shared_secret, commitment, new Fr(BigInt(leaf_index))]);
}
