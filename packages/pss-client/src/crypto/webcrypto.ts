import { fromBase64 } from "../wire/codec.js";
import { CryptoBackend, PssCryptoError } from "./backend.js";

// RFC 8410 PKCS#8 prefix for an Ed25519 private key, followed by the 32-byte seed.
const PKCS8_ED25519_PREFIX = Uint8Array.of(
  0x30,
  0x2e,
  0x02,
  0x01,
  0x00,
  0x30,
  0x05,
  0x06,
  0x03,
  0x2b,
  0x65,
  0x70,
  0x04,
  0x22,
  0x04,
  0x20,
);
const ED25519 = { name: "Ed25519" } as const;
const HMAC_SHA256 = { name: "HMAC", hash: "SHA-256" } as const;
const GCM_TAG_BITS = 128;

function subtle(): SubtleCrypto {
  const api = globalThis.crypto?.subtle;
  if (api === undefined) {
    throw new PssCryptoError("WebCrypto subtle is unavailable");
  }
  return api;
}

// WebCrypto's BufferSource excludes a view onto a SharedArrayBuffer, which the plain Uint8Array type
// still admits. The instanceof check is what makes the narrowing sound; the copy is the fallback for a
// shared buffer, which no PSS caller produces but the type system cannot rule out.
function source(data: Uint8Array): Uint8Array<ArrayBuffer> {
  if (data.buffer instanceof ArrayBuffer) {
    return data as Uint8Array<ArrayBuffer>;
  }
  const copy = new Uint8Array(data.length);
  copy.set(data);
  return copy;
}

function bytes(buffer: ArrayBuffer): Uint8Array {
  return new Uint8Array(buffer);
}

function base64UrlToBytes(text: string): Uint8Array {
  const standard = text.replace(/-/g, "+").replace(/_/g, "/");
  const padding = (4 - (standard.length % 4)) % 4;
  return fromBase64(standard + "=".repeat(padding), "Ed25519 JWK x");
}

function pkcs8(seed: Uint8Array): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(PKCS8_ED25519_PREFIX.length + seed.length);
  out.set(PKCS8_ED25519_PREFIX, 0);
  out.set(seed, PKCS8_ED25519_PREFIX.length);
  return out;
}

async function privateKey(
  seed: Uint8Array,
  extractable: boolean,
): Promise<CryptoKey> {
  return subtle().importKey("pkcs8", pkcs8(seed), ED25519, extractable, [
    "sign",
  ]);
}

export const webCryptoBackend: CryptoBackend = {
  name: "webcrypto",

  randomBytes(length: number): Uint8Array {
    const out = new Uint8Array(length);
    globalThis.crypto.getRandomValues(out);
    return out;
  },

  async sha256(data: Uint8Array): Promise<Uint8Array> {
    return bytes(await subtle().digest("SHA-256", source(data)));
  },

  async hmacSha256(key: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
    const imported = await subtle().importKey(
      "raw",
      source(key),
      HMAC_SHA256,
      false,
      ["sign"],
    );
    return bytes(await subtle().sign("HMAC", imported, source(data)));
  },

  async aesGcmSeal(
    key: Uint8Array,
    nonce: Uint8Array,
    aad: Uint8Array,
    plaintext: Uint8Array,
  ): Promise<Uint8Array> {
    const imported = await subtle().importKey(
      "raw",
      source(key),
      "AES-GCM",
      false,
      ["encrypt"],
    );
    return bytes(
      await subtle().encrypt(
        {
          name: "AES-GCM",
          iv: source(nonce),
          additionalData: source(aad),
          tagLength: GCM_TAG_BITS,
        },
        imported,
        source(plaintext),
      ),
    );
  },

  async aesGcmOpen(
    key: Uint8Array,
    nonce: Uint8Array,
    aad: Uint8Array,
    sealed: Uint8Array,
  ): Promise<Uint8Array> {
    const imported = await subtle().importKey(
      "raw",
      source(key),
      "AES-GCM",
      false,
      ["decrypt"],
    );
    try {
      return bytes(
        await subtle().decrypt(
          {
            name: "AES-GCM",
            iv: source(nonce),
            additionalData: source(aad),
            tagLength: GCM_TAG_BITS,
          },
          imported,
          source(sealed),
        ),
      );
    } catch {
      throw new PssCryptoError("AES-GCM authentication failed");
    }
  },

  // WebCrypto cannot export a public key from a private one, but the JWK form of an OKP private key
  // carries the public point in `x` (RFC 8037 section 2), which is the only way to reach it here.
  async ed25519PublicKey(seed: Uint8Array): Promise<Uint8Array> {
    const jwk = await subtle().exportKey("jwk", await privateKey(seed, true));
    if (jwk.x === undefined) {
      throw new PssCryptoError("Ed25519 JWK carried no public point");
    }
    return base64UrlToBytes(jwk.x);
  },

  async ed25519Sign(
    seed: Uint8Array,
    message: Uint8Array,
  ): Promise<Uint8Array> {
    return bytes(
      await subtle().sign(
        ED25519,
        await privateKey(seed, false),
        source(message),
      ),
    );
  },

  async ed25519Verify(
    publicKey: Uint8Array,
    message: Uint8Array,
    signature: Uint8Array,
  ): Promise<boolean> {
    const imported = await subtle().importKey(
      "raw",
      source(publicKey),
      ED25519,
      false,
      ["verify"],
    );
    return subtle().verify(
      ED25519,
      imported,
      source(signature),
      source(message),
    );
  },
};
