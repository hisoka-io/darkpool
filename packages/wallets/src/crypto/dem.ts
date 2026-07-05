import { Fr } from "@aztec/foundation/fields";
import { Poseidon } from "./Poseidon.js";
import { toFr } from "./fields.js";
import { ENC_DOMAIN } from "./constants.js";

// Zero-AES Poseidon2 stream DEM (CTR over a Poseidon2 PRF keyed by CEK; Poseidon2 eprint 2023/323).
// Operates on the 7 TRANSMITTED note fields directly (no AES, no byte-packing), fixed index order
// k=0..6: [note_version, asset_id, note_type, conditions_hash, value, owner, parents] (psi is derived
// from CEK and is NEVER transmitted). Order is fixed by the caller and MUST match Noir shared/src/dem.nr.
export const DEM_FIELDS = 7;

// keystream[k] = Poseidon2(CEK, ENC_DOMAIN, k); each field uses an independent 3-input permutation.
async function demKeystream(cek: Fr, k: number): Promise<Fr> {
  return Poseidon.hash([cek, toFr(ENC_DOMAIN), toFr(k)]);
}

// encrypt: ciphertext[k] = plaintext[k] + keystream[k] (mod p). Sign is LOCKED (decrypt subtracts).
export async function demEncrypt(cek: Fr, plaintext: Fr[]): Promise<Fr[]> {
  if (plaintext.length !== DEM_FIELDS) {
    throw new Error(
      `DEM encrypt expects ${DEM_FIELDS} plaintext fields, got ${plaintext.length}`,
    );
  }
  const ciphertext: Fr[] = [];
  for (let k = 0; k < DEM_FIELDS; k++) {
    ciphertext.push(plaintext[k].add(await demKeystream(cek, k)));
  }
  return ciphertext;
}

// decrypt: plaintext[k] = ciphertext[k] - keystream[k] (mod p).
export async function demDecrypt(cek: Fr, ciphertext: Fr[]): Promise<Fr[]> {
  if (ciphertext.length !== DEM_FIELDS) {
    throw new Error(
      `DEM decrypt expects ${DEM_FIELDS} ciphertext fields, got ${ciphertext.length}`,
    );
  }
  const plaintext: Fr[] = [];
  for (let k = 0; k < DEM_FIELDS; k++) {
    plaintext.push(ciphertext[k].sub(await demKeystream(cek, k)));
  }
  return plaintext;
}
