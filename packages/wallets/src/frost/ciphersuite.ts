// Group + hash ops the generic FROST protocol is parameterized over (hash preimages per RFC 9591 4.4-4.6).

export interface Commitment<G> {
  id: bigint;
  D: G;
  E: G;
}

export interface Ciphersuite<G> {
  readonly name: string;

  readonly generator: G;
  readonly identity: G;
  add(a: G, b: G): G;
  scalarMul(k: bigint, p: G): G;
  negate(p: G): G;
  eq(a: G, b: G): boolean;

  readonly order: bigint;

  nonceScalar(random32: Uint8Array, secret: bigint): bigint | Promise<bigint>;
  bindingFactor(
    gpk: G,
    msg: Uint8Array,
    commitments: Commitment<G>[],
    id: bigint,
  ): bigint | Promise<bigint>;
  challenge(R: G, gpk: G, msg: Uint8Array): bigint | Promise<bigint>;
}
