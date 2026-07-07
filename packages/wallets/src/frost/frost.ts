// Generic FROST 2-round threshold Schnorr signing (RFC 9591), parameterized over a Ciphersuite. This is the
// protocol LOGIC certified by the RFC 9591 KAT (via the ristretto255 ciphersuite) and run in production over
// BabyJubJub+Poseidon2. Sections cited are RFC 9591.

import { Ciphersuite, Commitment } from "./ciphersuite.js";

/** Round-1 secret nonces (hiding d_i, binding e_i). ONE-TIME use: a reuse lets an observer solve
 *  sk*lambda = (z1 - z2)/(c1 - c2). Never log. The KAT feeds a plain object (fixed recorded randomness, one
 *  shot by construction); production draws via `commit`, which returns a consume-once `NonceHandle`. */
export interface Nonces {
  d: bigint;
  e: bigint;
}

/** Consume-once wrapper `commit` returns: the FIRST `signShare` marks it used and a SECOND `signShare` with
 *  the same handle THROWS, so a crash-replay / double-submit can never reuse (d,e) (nonce reuse extracts the
 *  secret share). A plain `Nonces` object is NOT tracked -- that path exists only for the fixed-randomness KAT
 *  where reuse is deliberate and safe. Never log d/e. */
export class NonceHandle implements Nonces {
  readonly d: bigint;
  readonly e: bigint;
  #consumed = false;
  constructor(d: bigint, e: bigint) {
    this.d = d;
    this.e = e;
  }
  markConsumed(): void {
    if (this.#consumed)
      throw new Error(
        "frost: one-time nonce reused (round-1 handle already consumed)",
      );
    this.#consumed = true;
  }
}

export interface Signature<G> {
  R: G;
  z: bigint;
}

function mod(x: bigint, m: bigint): bigint {
  return ((x % m) + m) % m;
}

function modInverse(x: bigint, m: bigint): bigint {
  // Extended Euclid; m is prime here but this is general.
  let [old_r, r] = [mod(x, m), m];
  let [old_s, s] = [1n, 0n];
  while (r !== 0n) {
    const q = old_r / r;
    [old_r, r] = [r, old_r - q * r];
    [old_s, s] = [s, old_s - q * s];
  }
  if (old_r !== 1n) throw new Error("frost: scalar has no inverse mod order");
  return mod(old_s, m);
}

function sortById<G>(commitments: Commitment<G>[]): Commitment<G>[] {
  return [...commitments].sort((a, b) =>
    a.id < b.id ? -1 : a.id > b.id ? 1 : 0,
  );
}

/** Round 1: generate a hedged one-time nonce pair and its public commitment for signer `id` (RFC 5.1).
 *  `secret` is the signer's secret share; `hidingRandom` and `bindingRandom` MUST each be 32 fresh CSPRNG
 *  bytes per invocation (hedged, non-deterministic -- a deterministic nonce is a multiparty key-recovery
 *  vector). Production draws two fresh values; the RFC KAT feeds its recorded randomness. */
export async function commit<G>(
  cs: Ciphersuite<G>,
  id: bigint,
  secret: bigint,
  hidingRandom: Uint8Array,
  bindingRandom: Uint8Array,
): Promise<{ nonces: NonceHandle; commitment: Commitment<G> }> {
  const d = await cs.nonceScalar(hidingRandom, secret);
  const e = await cs.nonceScalar(bindingRandom, secret);
  const D = cs.scalarMul(d, cs.generator);
  const E = cs.scalarMul(e, cs.generator);
  return { nonces: new NonceHandle(d, e), commitment: { id, D, E } };
}

/** Per-participant binding factors rho_i over the (sorted) commitment list (RFC 4.4). */
export async function bindingFactors<G>(
  cs: Ciphersuite<G>,
  gpk: G,
  msg: Uint8Array,
  commitments: Commitment<G>[],
): Promise<Map<bigint, bigint>> {
  const sorted = sortById(commitments);
  const out = new Map<bigint, bigint>();
  for (const c of sorted) {
    out.set(c.id, await cs.bindingFactor(gpk, msg, sorted, c.id));
  }
  return out;
}

/** Group commitment R = sum_i (D_i + rho_i*E_i) (RFC 4.5). */
export function groupCommitment<G>(
  cs: Ciphersuite<G>,
  commitments: Commitment<G>[],
  rhos: Map<bigint, bigint>,
): G {
  let R = cs.identity;
  for (const c of sortById(commitments)) {
    const rho = rhos.get(c.id);
    if (rho === undefined)
      throw new Error(`frost: missing binding factor for ${c.id}`);
    R = cs.add(R, cs.add(c.D, cs.scalarMul(rho, c.E)));
  }
  return R;
}

/** Lagrange coefficient lambda_i(0) over the ACTUAL signer identifier set (RFC 4.2), mod the group order. */
export function lagrangeCoefficient<G>(
  cs: Ciphersuite<G>,
  id: bigint,
  signerSet: bigint[],
): bigint {
  const m = cs.order;
  let num = 1n;
  let den = 1n;
  for (const j of signerSet) {
    if (j === id) continue;
    num = mod(num * mod(j, m), m);
    den = mod(den * mod(j - id, m), m);
  }
  return mod(num * modInverse(den, m), m);
}

/** Round 2 core: the partial-signature math z_i = d_i + e_i*rho_i + lambda_i*sk_i*c (RFC 5.2) with NO
 *  one-time-nonce enforcement. This is the KAT / low-level path (the RFC vector deliberately reuses its
 *  recorded nonces across re-derivations); it parallels `aggregate` (pure). Production MUST call `signShare`,
 *  which only accepts a consume-once `NonceHandle` and burns it before delegating here. */
export async function signShareUnchecked<G>(
  cs: Ciphersuite<G>,
  id: bigint,
  nonces: Nonces,
  secretShare: bigint,
  gpk: G,
  msg: Uint8Array,
  commitments: Commitment<G>[],
): Promise<bigint> {
  const m = cs.order;
  const signerSet = commitments.map((c) => c.id);
  const rhos = await bindingFactors(cs, gpk, msg, commitments);
  const R = groupCommitment(cs, commitments, rhos);
  const c = await cs.challenge(R, gpk, msg);
  const lambda = lagrangeCoefficient(cs, id, signerSet);
  const rho = rhos.get(id);
  if (rho === undefined)
    throw new Error(`frost: signer ${id} not in commitment list`);
  return mod(
    nonces.d +
      mod(nonces.e * rho, m) +
      mod(mod(lambda * secretShare, m) * c, m),
    m,
  );
}

/** Round 2 (production): a signer's partial signature (RFC 5.2). Accepts ONLY a consume-once `NonceHandle`
 *  (a bare {d,e} that would bypass single-use is not assignable), and burns it FIRST so a crash-replay /
 *  double-submit with the same handle throws before any share math -- nonce reuse extracts the secret share. */
export async function signShare<G>(
  cs: Ciphersuite<G>,
  id: bigint,
  nonces: NonceHandle,
  secretShare: bigint,
  gpk: G,
  msg: Uint8Array,
  commitments: Commitment<G>[],
): Promise<bigint> {
  nonces.markConsumed();
  return signShareUnchecked(cs, id, nonces, secretShare, gpk, msg, commitments);
}

/** Coordinator check that a partial is well-formed (RFC 5.3): z_i*G == D_i + rho_i*E_i + (c*lambda_i)*PK_i.
 *  A failure identifies a misbehaving signer (identifiable abort), so equivocation degrades to DoS, never
 *  forgery. `publicShare` = PK_i = the signer's verification share. */
export async function verifySignatureShare<G>(
  cs: Ciphersuite<G>,
  id: bigint,
  zShare: bigint,
  publicShare: G,
  gpk: G,
  msg: Uint8Array,
  commitments: Commitment<G>[],
): Promise<boolean> {
  const m = cs.order;
  const signerSet = commitments.map((c) => c.id);
  const rhos = await bindingFactors(cs, gpk, msg, commitments);
  const R = groupCommitment(cs, commitments, rhos);
  const c = await cs.challenge(R, gpk, msg);
  const commitment = commitments.find((k) => k.id === id);
  if (commitment === undefined) return false;
  const rho = rhos.get(id)!;
  const lambda = lagrangeCoefficient(cs, id, signerSet);
  const lhs = cs.scalarMul(zShare, cs.generator);
  const commShare = cs.add(commitment.D, cs.scalarMul(rho, commitment.E));
  const rhs = cs.add(commShare, cs.scalarMul(mod(c * lambda, m), publicShare));
  return cs.eq(lhs, rhs);
}

/** Aggregate partials into the final signature (R, z), z = sum z_i (RFC 5.3). PURE: no per-share verify (the
 *  KAT feeds already-checked shares). A production coordinator MUST use `coordinatorAggregate` instead. */
export function aggregate<G>(
  cs: Ciphersuite<G>,
  R: G,
  zShares: bigint[],
): Signature<G> {
  const m = cs.order;
  let z = 0n;
  for (const zi of zShares) z = mod(z + zi, m);
  return { R, z };
}

/** The coordinator aggregation path: reject duplicate/sub-threshold shares, then verify EVERY partial
 *  (RFC 5.3 identifiable abort) before summing, so a malicious or replayed z_i is attributed and rejected
 *  rather than silently corrupting the aggregate (wasted-gas DoS). The dedup + `threshold` gate is
 *  defense-in-depth over the final Schnorr check: a resubmitted share cannot be counted twice and a
 *  sub-quorum set cannot open a signature. This is the mandatory gate for the production signing coordinator
 *  (the networked collect/verify/aggregate round is a pre-mainnet gate); `aggregate` stays unguarded for the
 *  KAT/low-level path. */
export async function coordinatorAggregate<G>(
  cs: Ciphersuite<G>,
  R: G,
  gpk: G,
  msg: Uint8Array,
  commitments: Commitment<G>[],
  partials: { id: bigint; z: bigint; publicShare: G }[],
  threshold: number,
): Promise<Signature<G>> {
  const seen = new Set<bigint>();
  for (const s of partials) {
    if (seen.has(s.id))
      throw new Error(
        `frost: duplicate signature share from signer ${s.id} (replay rejected)`,
      );
    seen.add(s.id);
  }
  if (seen.size < threshold)
    throw new Error(
      `frost: ${seen.size} distinct shares below threshold ${threshold}`,
    );

  for (const s of partials) {
    const ok = await verifySignatureShare(
      cs,
      s.id,
      s.z,
      s.publicShare,
      gpk,
      msg,
      commitments,
    );
    if (!ok)
      throw new Error(
        `frost: signature share from signer ${s.id} failed verification (identifiable abort)`,
      );
  }
  return aggregate(
    cs,
    R,
    partials.map((s) => s.z),
  );
}

/** Verify a FROST/Schnorr signature: z*G == R + c*gpk (RFC 3.1). The threshold signature is identical to a
 *  single-key Schnorr signature under gpk. */
export async function verify<G>(
  cs: Ciphersuite<G>,
  gpk: G,
  msg: Uint8Array,
  sig: Signature<G>,
): Promise<boolean> {
  const c = await cs.challenge(sig.R, gpk, msg);
  const lhs = cs.scalarMul(sig.z, cs.generator);
  const rhs = cs.add(sig.R, cs.scalarMul(c, gpk));
  return cs.eq(lhs, rhs);
}
