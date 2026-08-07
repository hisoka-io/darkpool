import { PssProtocolError } from "./errors.js";

const BASE64_ALPHABET =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const BASE64_SHAPE = /^[A-Za-z0-9+/]*={0,2}$/;
const HEX_SHAPE = /^0x[0-9a-f]*$/;
const HEX_RAW_SHAPE = /^[0-9a-f]*$/;
const U64_BYTES = 8;

const BASE64_INDEX: ReadonlyMap<string, number> = new Map(
  Array.from(BASE64_ALPHABET, (char, index) => [char, index]),
);

export function utf8(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

export function concatBytes(...parts: readonly Uint8Array[]): Uint8Array {
  let total = 0;
  for (const part of parts) total += part.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

export function toBase64(bytes: Uint8Array): string {
  let out = "";
  const full = bytes.length - (bytes.length % 3);
  for (let i = 0; i < full; i += 3) {
    const word = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
    out +=
      BASE64_ALPHABET[(word >> 18) & 63] +
      BASE64_ALPHABET[(word >> 12) & 63] +
      BASE64_ALPHABET[(word >> 6) & 63] +
      BASE64_ALPHABET[word & 63];
  }
  const remaining = bytes.length - full;
  if (remaining === 1) {
    const word = bytes[full] << 16;
    out +=
      BASE64_ALPHABET[(word >> 18) & 63] +
      BASE64_ALPHABET[(word >> 12) & 63] +
      "==";
  } else if (remaining === 2) {
    const word = (bytes[full] << 16) | (bytes[full + 1] << 8);
    out +=
      BASE64_ALPHABET[(word >> 18) & 63] +
      BASE64_ALPHABET[(word >> 12) & 63] +
      BASE64_ALPHABET[(word >> 6) & 63] +
      "=";
  }
  return out;
}

// Round-trips through toBase64 to reject non-canonical encodings. Two distinct strings decoding to the
// same bytes would let a signed request be rewritten without invalidating its signature over the decoded
// form, so the decoder accepts exactly one spelling per byte string.
export function fromBase64(text: string, label: string): Uint8Array {
  if (text.length % 4 !== 0 || !BASE64_SHAPE.test(text)) {
    throw new PssProtocolError(`${label} is not base64`);
  }
  const padding = text.endsWith("==") ? 2 : text.endsWith("=") ? 1 : 0;
  const out = new Uint8Array((text.length / 4) * 3 - padding);
  let offset = 0;
  for (let i = 0; i < text.length; i += 4) {
    let word = 0;
    for (let j = 0; j < 4; j++) {
      const char = text[i + j];
      const value = char === "=" ? 0 : BASE64_INDEX.get(char);
      if (value === undefined) {
        throw new PssProtocolError(`${label} is not base64`);
      }
      word = (word << 6) | value;
    }
    const triple = [(word >> 16) & 255, (word >> 8) & 255, word & 255];
    for (const byte of triple) {
      if (offset < out.length) out[offset++] = byte;
    }
  }
  if (toBase64(out) !== text) {
    throw new PssProtocolError(`${label} is not canonical base64`);
  }
  return out;
}

export function toHexRaw(bytes: Uint8Array): string {
  let out = "";
  for (const byte of bytes) out += byte.toString(16).padStart(2, "0");
  return out;
}

export function fromHexRaw(text: string, label: string): Uint8Array {
  if (!HEX_RAW_SHAPE.test(text) || text.length % 2 !== 0) {
    throw new PssProtocolError(`${label} is not unprefixed lowercase hex`);
  }
  const out = new Uint8Array(text.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(text.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export function toHex(bytes: Uint8Array): string {
  return `0x${toHexRaw(bytes)}`;
}

export function fromHex(text: string, label: string): Uint8Array {
  if (!HEX_SHAPE.test(text) || text.length % 2 !== 0) {
    throw new PssProtocolError(`${label} is not 0x-prefixed lowercase hex`);
  }
  return fromHexRaw(text.slice(2), label);
}

export function assertLength(
  bytes: Uint8Array,
  expected: number,
  label: string,
): Uint8Array {
  if (bytes.length !== expected) {
    throw new PssProtocolError(
      `${label} must be ${expected} bytes, got ${bytes.length}`,
    );
  }
  return bytes;
}

export function assertCount(value: unknown, label: string): number {
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    value < 0 ||
    Object.is(value, -0)
  ) {
    throw new PssProtocolError(
      `${label} must be a non-negative safe integer, got ${String(value)}`,
    );
  }
  return value;
}

export function u64be(value: number, label: string): Uint8Array {
  const out = new Uint8Array(U64_BYTES);
  let remaining = BigInt(assertCount(value, label));
  for (let i = U64_BYTES - 1; i >= 0; i--) {
    out[i] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return out;
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}
