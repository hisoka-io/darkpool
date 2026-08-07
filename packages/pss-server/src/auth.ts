import { createHash, createPublicKey, verify } from "node:crypto";
import { ACCOUNT_ID_BYTES, bytesEqual } from "@hisoka/pss-client/wire";

// RFC 8410 section 4: the SubjectPublicKeyInfo header for id-Ed25519. node:crypto imports a public key
// only as SPKI, PEM or JWK, so the 32 raw bytes on the wire are wrapped rather than passed through.
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

export function sha256(bytes: Uint8Array): Uint8Array {
  return Uint8Array.from(createHash("sha256").update(bytes).digest());
}

export function accountIdOf(authPk: Uint8Array): Uint8Array {
  return sha256(authPk);
}

export function ownsAccount(
  authPk: Uint8Array,
  accountId: Uint8Array,
): boolean {
  return (
    accountId.length === ACCOUNT_ID_BYTES &&
    bytesEqual(accountIdOf(authPk), accountId)
  );
}

export function verifyEd25519(
  message: Uint8Array,
  signature: Uint8Array,
  authPk: Uint8Array,
): boolean {
  try {
    const key = createPublicKey({
      key: Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(authPk)]),
      format: "der",
      type: "spki",
    });
    return verify(null, message, key, signature);
  } catch {
    return false;
  }
}

export function withinSkew(
  timestamp: number,
  nowSeconds: number,
  skewSeconds: number,
): boolean {
  return Math.abs(timestamp - nowSeconds) < skewSeconds;
}
