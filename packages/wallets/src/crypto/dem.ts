import { Fr } from "@aztec/foundation/fields";
import { Poseidon } from "./Poseidon.js";
import { toFr } from "./fields.js";
import { ENC_DOMAIN } from "./constants.js";

// Poseidon2 stream DEM (eprint 2023/323) over the 7 transmitted note fields, fixed order
// [note_version, asset_id, note_type, conditions_hash, value, owner, parents]; psi is derived from
// CEK, never transmitted. Order MUST match Noir shared/src/dem.nr.
export const DEM_FIELDS = 7;

async function demKeystream(cek: Fr, k: number): Promise<Fr> {
  return Poseidon.hash([cek, toFr(ENC_DOMAIN), toFr(k)]);
}

// Add-pad; sign is LOCKED (decrypt subtracts the same pad) and MUST match Noir.
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
