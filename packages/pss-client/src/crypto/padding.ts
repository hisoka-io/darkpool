import { PAD_TIERS } from "../wire/constants.js";
import { PssCryptoError } from "./backend.js";

const LENGTH_PREFIX_BYTES = 4;

export function maxPayloadBytes(): number {
  return PAD_TIERS[PAD_TIERS.length - 1] - LENGTH_PREFIX_BYTES;
}

export function tierFor(payloadLength: number): number {
  const needed = payloadLength + LENGTH_PREFIX_BYTES;
  for (const tier of PAD_TIERS) {
    if (needed <= tier) return tier;
  }
  throw new PssCryptoError(
    `state of ${payloadLength} bytes exceeds the largest tier; the payload must shrink ` +
      `(largest supported payload is ${maxPayloadBytes()} bytes)`,
  );
}

// Only three plaintext lengths ever reach the AEAD, so the ciphertext length carries at most a
// three-way distinction rather than the size of the wallet behind it.
export function pad(payload: Uint8Array): Uint8Array {
  const tier = tierFor(payload.length);
  const out = new Uint8Array(tier);
  const view = new DataView(out.buffer, out.byteOffset, out.byteLength);
  view.setUint32(0, payload.length, false);
  out.set(payload, LENGTH_PREFIX_BYTES);
  return out;
}

export function unpad(padded: Uint8Array): Uint8Array {
  if (!(PAD_TIERS as readonly number[]).includes(padded.length)) {
    throw new PssCryptoError(
      `padded plaintext is ${padded.length} bytes, which is not a padding tier`,
    );
  }
  const view = new DataView(
    padded.buffer,
    padded.byteOffset,
    padded.byteLength,
  );
  const length = view.getUint32(0, false);
  if (length > padded.length - LENGTH_PREFIX_BYTES) {
    throw new PssCryptoError(
      `padded plaintext claims ${length} bytes inside a ${padded.length} byte tier`,
    );
  }
  const end = LENGTH_PREFIX_BYTES + length;
  for (let i = end; i < padded.length; i++) {
    if (padded[i] !== 0) {
      throw new PssCryptoError("padding is not zero filled");
    }
  }
  return padded.slice(LENGTH_PREFIX_BYTES, end);
}
