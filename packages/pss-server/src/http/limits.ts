import {
  ED25519_PUBLIC_KEY_BYTES,
  ED25519_SIGNATURE_BYTES,
  GCM_NONCE_BYTES,
  INVITE_CODE_MAX_CHARS,
} from "@hisoka/pss-client/wire";

const BASE64_GROUP_BYTES = 3;
const BASE64_GROUP_CHARS = 4;

export function base64Chars(bytes: number): number {
  return Math.ceil(bytes / BASE64_GROUP_BYTES) * BASE64_GROUP_CHARS;
}

// Null when the text cannot be base64 at all; the caller then lets the wire parser produce the error.
export function base64Bytes(text: string): number | null {
  if (text.length % BASE64_GROUP_CHARS !== 0) return null;
  const padding = text.endsWith("==") ? 2 : text.endsWith("=") ? 1 : 0;
  return (text.length / BASE64_GROUP_CHARS) * BASE64_GROUP_BYTES - padding;
}

// Measured from the encoding itself rather than picked: the skeleton is the widest legal JSON envelope
// with every field empty, and each field's own maximum is added back from the wire constants.
function envelopeChars(skeleton: Readonly<Record<string, unknown>>): number {
  return JSON.stringify(skeleton).length;
}

const PUT_ENVELOPE_CHARS = envelopeChars({
  version: Number.MAX_SAFE_INTEGER,
  prevVersion: Number.MAX_SAFE_INTEGER,
  timestamp: Number.MAX_SAFE_INTEGER,
  nonce: "",
  ciphertext: "",
  authPk: "",
  sig: "",
  invite: "",
});

const DELETE_ENVELOPE_CHARS = envelopeChars({
  timestamp: Number.MAX_SAFE_INTEGER,
  nonce: "",
  authPk: "",
  sig: "",
});

// The skeleton is the tightest legal envelope, so a compactly serialised body sits within a handful of
// bytes of it and a create carrying a maximum-length invite sits exactly on it. A client that
// pretty-prints its JSON is still sending a legal request, so both caps carry headroom rather than
// assuming the serialiser. DELETE keeps a smaller allowance of its own: its body is short and
// fixed-shape, and it is the one route with no recovery.
const DELETE_HEADROOM_CHARS = 256;

const CREDENTIAL_CHARS =
  base64Chars(GCM_NONCE_BYTES) +
  base64Chars(ED25519_PUBLIC_KEY_BYTES) +
  base64Chars(ED25519_SIGNATURE_BYTES);

export const MAX_DELETE_BODY_BYTES =
  DELETE_ENVELOPE_CHARS + CREDENTIAL_CHARS + DELETE_HEADROOM_CHARS;

export function maxPutBodyBytes(
  maxCiphertextBytes: number,
  headroomBytes: number,
): number {
  return (
    PUT_ENVELOPE_CHARS +
    CREDENTIAL_CHARS +
    INVITE_CODE_MAX_CHARS +
    base64Chars(maxCiphertextBytes) +
    headroomBytes
  );
}
