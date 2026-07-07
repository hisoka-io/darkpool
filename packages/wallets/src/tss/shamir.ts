// Shamir secret sharing over the BabyJubJub prime-order subgroup: polynomial evaluation + Lagrange
// interpolation at x=0, ALL mod SUBORDER (research T7 -- a mod-BN254-Fr variant is silently catastrophic).
// Ported from threshold_compliance_poc.py (poly_eval / lagrange0), which is verified against the curve.

import { modSub, invSub, SUBORDER } from "./bjj.js";

/** Evaluate a polynomial (coefficients low-to-high, a_0 the secret) at x, mod SUBORDER (Horner). */
export function polyEval(coeffs: bigint[], x: bigint): bigint {
  const xr = modSub(x);
  let acc = 0n;
  for (let k = coeffs.length - 1; k >= 0; k--) {
    acc = modSub(acc * xr + coeffs[k]);
  }
  return acc;
}

/** Lagrange coefficient lambda_i(0) over the interpolation x-set `xs` (participant identifiers), mod
 *  SUBORDER: prod_{j!=i} x_j / (x_j - x_i). Throws on a duplicate identifier (zero denominator). */
export function lagrangeAtZero(i: bigint, xs: bigint[]): bigint {
  const ir = modSub(i);
  let num = 1n;
  let den = 1n;
  for (const j of xs) {
    const jr = modSub(j);
    if (jr === ir) continue;
    num = modSub(num * jr);
    den = modSub(den * modSub(jr - ir));
  }
  if (den === 0n)
    throw new Error("tss: duplicate identifier in interpolation set");
  return modSub(num * invSub(den));
}

/** Reconstruct f(0) from t verified shares {i: f(i)} over the quorum. Compliance never runs this on the
 *  secret c; it is used for the in-scalar consistency check and Lagrange-in-exponent's scalar analog. */
export function interpolateAtZero(
  shares: ReadonlyMap<bigint, bigint>,
  quorum: bigint[],
): bigint {
  let acc = 0n;
  for (const i of quorum) {
    const s = shares.get(i);
    if (s === undefined)
      throw new Error(`tss: missing share for identifier ${i}`);
    acc = modSub(acc + lagrangeAtZero(i, quorum) * s);
  }
  return acc;
}

export { SUBORDER };
