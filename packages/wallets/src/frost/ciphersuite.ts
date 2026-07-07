// A FROST ciphersuite: the group + scalar-field + hash operations the generic 2-round protocol is
// parameterized over. The SAME protocol code (frost.ts) is instantiated with:
//   - ristretto255 + SHA-512  (test-only) -> certified against the RFC 9591 known-answer vectors, so the
//     protocol LOGIC production runs is checked against independent official vectors;
//   - BabyJubJub + Poseidon2  (production) -> the in-pool multisig signer, whose group/hash ops carry their
//     own TS<->Noir parity KATs.
// Each ciphersuite owns its EXACT hash preimages (byte-concat + SHA for the standard curves per RFC 4.4-4.6;
// field-element Poseidon2 for BabyJubJub); the generic layer only composes them.

/** A round-1 public nonce commitment from one signer (RFC: hiding D_i, binding E_i). */
export interface Commitment<G> {
  id: bigint;
  D: G;
  E: G;
}

export interface Ciphersuite<G> {
  readonly name: string;

  // --- Group ---
  readonly generator: G;
  readonly identity: G;
  add(a: G, b: G): G;
  /** k*P with k reduced mod `order`. */
  scalarMul(k: bigint, p: G): G;
  negate(p: G): G;
  eq(a: G, b: G): boolean;

  // --- Scalar field (mod the prime group order) ---
  readonly order: bigint;

  // --- FROST hashes (RFC 9591 3.2 / 4.4-4.6); each ciphersuite implements the exact preimage) ---
  /** H3: hedged one-time nonce scalar from 32 fresh random bytes and the signer's secret. */
  nonceScalar(random32: Uint8Array, secret: bigint): bigint | Promise<bigint>;
  /** H1: per-participant binding factor rho_i, binding gpk + H4(msg) + H5(sorted commitment list) + id. */
  bindingFactor(
    gpk: G,
    msg: Uint8Array,
    commitments: Commitment<G>[],
    id: bigint,
  ): bigint | Promise<bigint>;
  /** H2: challenge c = H2(R, gpk, msg). */
  challenge(R: G, gpk: G, msg: Uint8Array): bigint | Promise<bigint>;
}
