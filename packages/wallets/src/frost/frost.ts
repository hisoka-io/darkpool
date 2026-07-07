// Generic FROST 2-round threshold Schnorr signing, ciphersuite-parameterized. Section refs are RFC 9591.

import { Ciphersuite, Commitment } from "./ciphersuite.js";

/** Round-1 secret nonces (hiding d_i, binding e_i). ONE-TIME: reuse solves sk*lambda = (z1-z2)/(c1-c2). Never log. */
export interface Nonces {
  d: bigint;
  e: bigint;
}

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

/** Round 1: hedged one-time nonce pair + public commitment for signer `id` (RFC 5.1). `hidingRandom`/
 *  `bindingRandom` MUST each be 32 fresh CSPRNG bytes per call -- a deterministic nonce is a key-recovery vector. */
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

/** NO nonce-reuse guard (KAT/low-level path). Production MUST call `signShare`. */
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

/** PURE: no per-share verify -- a production coordinator MUST use `coordinatorAggregate`. */
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
