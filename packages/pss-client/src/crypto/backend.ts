export class PssCryptoError extends Error {
  constructor(detail: string) {
    super(`PSS crypto: ${detail}`);
    this.name = "PssCryptoError";
  }
}

export type BackendName = "webcrypto" | "noble";

// The two implementations differ only in these primitives. Everything above them (the key schedule,
// the AEAD framing, the padding) is shared, so both backends agree by construction rather than by
// two parallel implementations being kept in step.
export interface CryptoBackend {
  readonly name: BackendName;
  randomBytes(length: number): Uint8Array;
  sha256(data: Uint8Array): Promise<Uint8Array>;
  hmacSha256(key: Uint8Array, data: Uint8Array): Promise<Uint8Array>;
  aesGcmSeal(
    key: Uint8Array,
    nonce: Uint8Array,
    aad: Uint8Array,
    plaintext: Uint8Array,
  ): Promise<Uint8Array>;
  aesGcmOpen(
    key: Uint8Array,
    nonce: Uint8Array,
    aad: Uint8Array,
    sealed: Uint8Array,
  ): Promise<Uint8Array>;
  ed25519PublicKey(seed: Uint8Array): Promise<Uint8Array>;
  ed25519Sign(seed: Uint8Array, message: Uint8Array): Promise<Uint8Array>;
  ed25519Verify(
    publicKey: Uint8Array,
    message: Uint8Array,
    signature: Uint8Array,
  ): Promise<boolean>;
}
