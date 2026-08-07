import { Collection } from "../wire/collection.js";
import { toBase64 } from "../wire/codec.js";
import { GCM_NONCE_BYTES, MAX_CIPHERTEXT_BYTES } from "../wire/constants.js";
import { deletePreimage, putPreimage } from "../wire/preimage.js";
import { DeleteAccountRequest, PutBlobRequest } from "../wire/types.js";
import { CryptoBackend, PssCryptoError } from "./backend.js";
import { PssKeys } from "./keys.js";

export interface PutRequestInput {
  readonly collection: Collection;
  readonly version: number;
  readonly prevVersion: number;
  readonly nonce: Uint8Array;
  readonly ciphertext: Uint8Array;
  readonly timestamp: number;
  readonly invite?: string;
}

export interface DeleteRequestInput {
  readonly nonce: Uint8Array;
  readonly timestamp: number;
}

export async function buildPutRequest(
  backend: CryptoBackend,
  keys: PssKeys,
  input: PutRequestInput,
): Promise<PutBlobRequest> {
  if (input.version <= input.prevVersion) {
    throw new PssCryptoError(
      `version ${input.version} must exceed prevVersion ${input.prevVersion}`,
    );
  }
  if (input.nonce.length !== GCM_NONCE_BYTES) {
    throw new PssCryptoError(
      `nonce must be ${GCM_NONCE_BYTES} bytes, got ${input.nonce.length}`,
    );
  }
  if (
    input.ciphertext.length === 0 ||
    input.ciphertext.length > MAX_CIPHERTEXT_BYTES
  ) {
    throw new PssCryptoError(
      `ciphertext must be 1..${MAX_CIPHERTEXT_BYTES} bytes, got ${input.ciphertext.length}`,
    );
  }
  const preimage = putPreimage({
    accountId: keys.accountId,
    collection: input.collection,
    version: input.version,
    prevVersion: input.prevVersion,
    ciphertextDigest: await backend.sha256(input.ciphertext),
    timestamp: input.timestamp,
  });
  const signature = await backend.ed25519Sign(keys.authSeed, preimage);
  const request: PutBlobRequest = {
    version: input.version,
    prevVersion: input.prevVersion,
    nonce: toBase64(input.nonce),
    ciphertext: toBase64(input.ciphertext),
    authPk: toBase64(keys.authPublicKey),
    sig: toBase64(signature),
    timestamp: input.timestamp,
  };
  return input.invite === undefined
    ? request
    : { ...request, invite: input.invite };
}

export async function buildDeleteRequest(
  backend: CryptoBackend,
  keys: PssKeys,
  input: DeleteRequestInput,
): Promise<DeleteAccountRequest> {
  if (input.nonce.length !== GCM_NONCE_BYTES) {
    throw new PssCryptoError(
      `delete nonce must be ${GCM_NONCE_BYTES} bytes, got ${input.nonce.length}`,
    );
  }
  const preimage = deletePreimage({
    accountId: keys.accountId,
    nonce: input.nonce,
    timestamp: input.timestamp,
  });
  const signature = await backend.ed25519Sign(keys.authSeed, preimage);
  return {
    authPk: toBase64(keys.authPublicKey),
    sig: toBase64(signature),
    timestamp: input.timestamp,
    nonce: toBase64(input.nonce),
  };
}
