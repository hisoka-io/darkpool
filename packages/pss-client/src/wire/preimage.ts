import { Collection } from "./collection.js";
import { assertLength, concatBytes, u64be, utf8 } from "./codec.js";
import {
  ACCOUNT_ID_BYTES,
  GCM_NONCE_BYTES,
  PREIMAGE_DELETE_PREFIX,
  PREIMAGE_PUT_PREFIX,
  SHA256_BYTES,
} from "./constants.js";
import { PssProtocolError } from "./errors.js";

export interface PutPreimageInput {
  readonly accountId: Uint8Array;
  readonly collection: Collection;
  readonly version: number;
  readonly prevVersion: number;
  readonly ciphertextDigest: Uint8Array;
  readonly timestamp: number;
}

export interface DeletePreimageInput {
  readonly accountId: Uint8Array;
  readonly nonce: Uint8Array;
  readonly timestamp: number;
}

function lengthPrefixedAscii(text: string): Uint8Array {
  const body = utf8(text);
  if (body.length > 0xff) {
    throw new PssProtocolError(`preimage field longer than 255 bytes: ${text}`);
  }
  return concatBytes(Uint8Array.of(body.length), body);
}

// Every field is fixed-width or length-prefixed, so the encoding is injective: no two distinct field
// tuples produce the same bytes. Without that, a signature over a concatenation is a signature over
// every re-split of it, which is how a signed write for one collection becomes a valid write for
// another. The collection is in the preimage for exactly that reason and must stay there.
export function putPreimage(input: PutPreimageInput): Uint8Array {
  assertLength(input.accountId, ACCOUNT_ID_BYTES, "accountId");
  assertLength(input.ciphertextDigest, SHA256_BYTES, "ciphertextDigest");
  return concatBytes(
    utf8(PREIMAGE_PUT_PREFIX),
    input.accountId,
    lengthPrefixedAscii(input.collection),
    u64be(input.version, "version"),
    u64be(input.prevVersion, "prevVersion"),
    input.ciphertextDigest,
    u64be(input.timestamp, "timestamp"),
  );
}

export function deletePreimage(input: DeletePreimageInput): Uint8Array {
  assertLength(input.accountId, ACCOUNT_ID_BYTES, "accountId");
  assertLength(input.nonce, GCM_NONCE_BYTES, "nonce");
  return concatBytes(
    utf8(PREIMAGE_DELETE_PREFIX),
    input.accountId,
    input.nonce,
    u64be(input.timestamp, "timestamp"),
  );
}
