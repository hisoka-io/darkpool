import { gcm } from "@noble/ciphers/aes";
import { ed25519 } from "@noble/curves/ed25519";
import { hmac } from "@noble/hashes/hmac";
import { sha256 } from "@noble/hashes/sha256";
import { randomBytes } from "@noble/hashes/utils";
import { CryptoBackend, PssCryptoError } from "./backend.js";

// React Native has no crypto.subtle, so this backend carries the same primitives in pure JS. Both
// backends are exercised against the same published vectors, which is what keeps them byte-identical.
export const nobleBackend: CryptoBackend = {
  name: "noble",

  randomBytes(length: number): Uint8Array {
    return randomBytes(length);
  },

  sha256(data: Uint8Array): Promise<Uint8Array> {
    return Promise.resolve(sha256(data));
  },

  hmacSha256(key: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
    return Promise.resolve(hmac(sha256, key, data));
  },

  aesGcmSeal(
    key: Uint8Array,
    nonce: Uint8Array,
    aad: Uint8Array,
    plaintext: Uint8Array,
  ): Promise<Uint8Array> {
    return Promise.resolve(gcm(key, nonce, aad).encrypt(plaintext));
  },

  aesGcmOpen(
    key: Uint8Array,
    nonce: Uint8Array,
    aad: Uint8Array,
    sealed: Uint8Array,
  ): Promise<Uint8Array> {
    try {
      return Promise.resolve(gcm(key, nonce, aad).decrypt(sealed));
    } catch {
      return Promise.reject(
        new PssCryptoError("AES-GCM authentication failed"),
      );
    }
  },

  ed25519PublicKey(seed: Uint8Array): Promise<Uint8Array> {
    return Promise.resolve(ed25519.getPublicKey(seed));
  },

  ed25519Sign(seed: Uint8Array, message: Uint8Array): Promise<Uint8Array> {
    return Promise.resolve(ed25519.sign(message, seed));
  },

  ed25519Verify(
    publicKey: Uint8Array,
    message: Uint8Array,
    signature: Uint8Array,
  ): Promise<boolean> {
    try {
      return Promise.resolve(ed25519.verify(signature, message, publicKey));
    } catch {
      return Promise.resolve(false);
    }
  },
};
