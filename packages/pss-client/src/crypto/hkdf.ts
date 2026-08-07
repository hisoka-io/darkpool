import { CryptoBackend, PssCryptoError } from "./backend.js";

const HASH_BYTES = 32;
const MAX_BLOCKS = 255;

// RFC 5869 section 2.3, the Expand half only. Neither WebCrypto nor node:crypto exposes Expand without
// Extract, so it is built here from the backend's HMAC and both backends therefore agree by
// construction. The frozen key schedule specifies Expand directly over k_state; see the builder report
// for why that deviates from the Extract-then-Expand form the design research specified.
export async function hkdfExpand(
  backend: CryptoBackend,
  prk: Uint8Array,
  info: Uint8Array,
  length: number,
): Promise<Uint8Array> {
  if (!Number.isInteger(length) || length <= 0) {
    throw new PssCryptoError(`HKDF length must be a positive integer`);
  }
  const blocks = Math.ceil(length / HASH_BYTES);
  if (blocks > MAX_BLOCKS) {
    throw new PssCryptoError(
      `HKDF cannot expand beyond ${MAX_BLOCKS * HASH_BYTES} bytes`,
    );
  }
  const out = new Uint8Array(length);
  let previous: Uint8Array = new Uint8Array(0);
  let written = 0;
  for (let counter = 1; counter <= blocks; counter++) {
    const input = new Uint8Array(previous.length + info.length + 1);
    input.set(previous, 0);
    input.set(info, previous.length);
    input[input.length - 1] = counter;
    previous = await backend.hmacSha256(prk, input);
    const take = Math.min(previous.length, length - written);
    out.set(previous.subarray(0, take), written);
    written += take;
  }
  return out;
}
