import { Fr } from "@aztec/foundation/fields";
import { Poseidon } from "../crypto/Poseidon.js";
import { PSI_DOMAIN } from "../crypto/constants.js";

/** Leaf blinder + nullifier key: psi = Poseidon2(CEK, PSI_DOMAIN). Byte-identical to Noir `psi`. */
export async function computePsi(cek: Fr): Promise<Fr> {
  return Poseidon.hash([cek, new Fr(PSI_DOMAIN)]);
}

/** Double-spend key: Poseidon2(psi, leaf_index). Byte-identical to Noir `nullifier`. */
export async function computeNullifier(psi: Fr, leafIndex: Fr): Promise<Fr> {
  return Poseidon.hash([psi, leafIndex]);
}
