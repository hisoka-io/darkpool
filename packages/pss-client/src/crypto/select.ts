import { CryptoBackend } from "./backend.js";
import { nobleBackend } from "./noble.js";
import { webCryptoBackend } from "./webcrypto.js";

const ED25519_PROBE_SEED = new Uint8Array(32);

let cached: Promise<CryptoBackend> | undefined;

// Capability detection rather than a build flag, and the probe is a real Ed25519 derivation rather than
// a feature-string check: Ed25519 reached WebCrypto later than HKDF and AES-GCM did, so a runtime that
// has `subtle` may still reject the curve.
async function probe(): Promise<CryptoBackend> {
  if (globalThis.crypto?.subtle === undefined) return nobleBackend;
  try {
    await webCryptoBackend.ed25519PublicKey(ED25519_PROBE_SEED);
    return webCryptoBackend;
  } catch {
    return nobleBackend;
  }
}

export function selectBackend(): Promise<CryptoBackend> {
  cached ??= probe();
  return cached;
}
