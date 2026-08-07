import { Collection } from "../wire/collection.js";
import { utf8 } from "../wire/codec.js";
import {
  ACCOUNT_ID_BYTES,
  DERIVED_KEY_BYTES,
  ED25519_PUBLIC_KEY_BYTES,
  HKDF_INFO_AUTH,
  HKDF_INFO_CELL_LABELS,
  HKDF_INFO_CELL_STATE,
  STATE_KEY_BYTES,
} from "../wire/constants.js";
import { CryptoBackend, PssCryptoError } from "./backend.js";
import { hkdfExpand } from "./hkdf.js";

const CELL_INFO: Readonly<Record<Collection, string>> = {
  state: HKDF_INFO_CELL_STATE,
  labels: HKDF_INFO_CELL_LABELS,
};

export interface PssKeys {
  readonly authSeed: Uint8Array;
  readonly authPublicKey: Uint8Array;
  readonly accountId: Uint8Array;
  readonly cellKey: Readonly<Record<Collection, Uint8Array>>;
}

// k_state arrives as 32 raw bytes and nothing else. Typing it as a field element would drag the
// wallet's Barretenberg WASM backend into a React Native bundle, and this package must stay free of
// every Hisoka type.
//
// Those bytes are a big-endian BN254 scalar-field element, not a uniform 32-byte string: the modulus is
// 254 bits, so byte 0 never exceeds 0x30 and the input carries about 254 bits of entropy. The frozen
// schedule feeds it straight to HKDF-Expand, which RFC 5869 section 3.3 reserves for input that is
// already a uniformly random key. The gap is about two bits and HMAC-SHA256 keyed this way is sound, so
// this is recorded rather than worked around; restoring the Extract step would change every accountId.
export async function deriveKeys(
  backend: CryptoBackend,
  stateKey: Uint8Array,
): Promise<PssKeys> {
  if (stateKey.length !== STATE_KEY_BYTES) {
    throw new PssCryptoError(
      `k_state must be exactly ${STATE_KEY_BYTES} bytes, got ${stateKey.length}`,
    );
  }
  const authSeed = await hkdfExpand(
    backend,
    stateKey,
    utf8(HKDF_INFO_AUTH),
    DERIVED_KEY_BYTES,
  );
  const authPublicKey = await backend.ed25519PublicKey(authSeed);
  if (authPublicKey.length !== ED25519_PUBLIC_KEY_BYTES) {
    throw new PssCryptoError(
      `Ed25519 public key must be ${ED25519_PUBLIC_KEY_BYTES} bytes`,
    );
  }
  const accountId = await backend.sha256(authPublicKey);
  if (accountId.length !== ACCOUNT_ID_BYTES) {
    throw new PssCryptoError(`accountId must be ${ACCOUNT_ID_BYTES} bytes`);
  }
  const [state, labels] = await Promise.all([
    hkdfExpand(backend, stateKey, utf8(CELL_INFO.state), DERIVED_KEY_BYTES),
    hkdfExpand(backend, stateKey, utf8(CELL_INFO.labels), DERIVED_KEY_BYTES),
  ]);
  return {
    authSeed,
    authPublicKey,
    accountId,
    cellKey: { state, labels },
  };
}
