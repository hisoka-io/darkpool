import { Fr } from "@aztec/foundation/fields";
import { Poseidon } from "../crypto/Poseidon.js";
import { toFr } from "../crypto/fields.js";
import { ENC_DOMAIN } from "../crypto/constants.js";
import { DEM_FIELDS } from "../crypto/dem.js";
import { NOTE_VERSION } from "../note/note.js";
import { CIPHERTEXT_KEPT_INDICES, HowlNoteRecord } from "./types.js";

/**
 * THE ONLY STRIP-AWARE CODE IN HOWL.
 *
 * The discovery service drops two of the seven transmitted ciphertext words because the client can
 * reconstruct both: word 0 is `note_version`, a compile-time constant, and word 5 is `owner`, which the
 * recipient must be able to compute or it could not spend the note.
 *
 * Reconstruct the CIPHERTEXT and hand the full seven words to `demDecrypt` unmodified. Decrypting the five
 * survivors directly and splicing plaintext would work today and would silently break the moment the DEM
 * stops being positional, and it would fork the parity KAT that keeps TS, Noir and Solidity byte-identical.
 */

// Mirrors the private keystream in crypto/dem.ts. Kept local rather than exported from there so the DEM
// surface stays encrypt/decrypt only; the parity KAT covers dem.ts and this agrees with it by construction.
async function keystream(cek: Fr, index: number): Promise<Fr> {
  return Poseidon.hash([cek, toFr(ENC_DOMAIN), toFr(index)]);
}

const STRIPPED_NOTE_VERSION_INDEX = 0;
const STRIPPED_OWNER_INDEX = 5;

/**
 * @param ownerCommitment the recipient's own `Poseidon2(pk.x, pk.y)`, recomputed locally, never fetched.
 */
export async function reconstructCiphertext(
  record: HowlNoteRecord,
  cek: Fr,
  ownerCommitment: Fr,
): Promise<Fr[]> {
  if (record.ciphertextKept.length !== CIPHERTEXT_KEPT_INDICES.length) {
    throw new Error(
      `record carries ${record.ciphertextKept.length} kept words, expected ${CIPHERTEXT_KEPT_INDICES.length}`,
    );
  }

  const full = new Array<Fr | undefined>(DEM_FIELDS);
  CIPHERTEXT_KEPT_INDICES.forEach((wordIndex, i) => {
    full[wordIndex] = record.ciphertextKept[i];
  });

  const [versionPad, ownerPad] = await Promise.all([
    keystream(cek, STRIPPED_NOTE_VERSION_INDEX),
    keystream(cek, STRIPPED_OWNER_INDEX),
  ]);
  full[STRIPPED_NOTE_VERSION_INDEX] = new Fr(
    (NOTE_VERSION.toBigInt() + versionPad.toBigInt()) % Fr.MODULUS,
  );
  full[STRIPPED_OWNER_INDEX] = new Fr(
    (ownerCommitment.toBigInt() + ownerPad.toBigInt()) % Fr.MODULUS,
  );

  const missing = full.findIndex((w) => w === undefined);
  if (missing !== -1) {
    throw new Error(`reconstructed ciphertext is missing word ${missing}`);
  }
  return full as Fr[];
}
