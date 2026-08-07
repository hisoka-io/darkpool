import { cellAad } from "../wire/aad.js";
import { Collection } from "../wire/collection.js";
import { GCM_NONCE_BYTES, GCM_TAG_BYTES } from "../wire/constants.js";
import { CryptoBackend, PssCryptoError } from "./backend.js";
import { pad, unpad } from "./padding.js";

export interface SealedCell {
  readonly nonce: Uint8Array;
  readonly ciphertext: Uint8Array;
}

export interface CellContext {
  readonly collection: Collection;
  readonly version: number;
}

// The nonce is drawn fresh from the CSPRNG on every seal and is never a counter and never derived. A
// repeated (key, nonce) under GCM leaks the XOR of both plaintexts and forges the authentication tag,
// and the cell key is stable for the life of the account, so there is no counter that could be safe.
export async function sealCell(
  backend: CryptoBackend,
  cellKey: Uint8Array,
  context: CellContext,
  payload: Uint8Array,
): Promise<SealedCell> {
  const nonce = backend.randomBytes(GCM_NONCE_BYTES);
  if (nonce.length !== GCM_NONCE_BYTES) {
    throw new PssCryptoError(`nonce must be ${GCM_NONCE_BYTES} bytes`);
  }
  const aad = cellAad(context.collection, context.version);
  const ciphertext = await backend.aesGcmSeal(
    cellKey,
    nonce,
    aad,
    pad(payload),
  );
  return { nonce, ciphertext };
}

export async function openCell(
  backend: CryptoBackend,
  cellKey: Uint8Array,
  context: CellContext,
  cell: SealedCell,
): Promise<Uint8Array> {
  if (cell.nonce.length !== GCM_NONCE_BYTES) {
    throw new PssCryptoError(
      `nonce must be ${GCM_NONCE_BYTES} bytes, got ${cell.nonce.length}`,
    );
  }
  if (cell.ciphertext.length <= GCM_TAG_BYTES) {
    throw new PssCryptoError(
      "ciphertext is shorter than its authentication tag",
    );
  }
  const aad = cellAad(context.collection, context.version);
  return unpad(
    await backend.aesGcmOpen(cellKey, cell.nonce, aad, cell.ciphertext),
  );
}
