// Feldman verifiable secret sharing: a dealer publishes commitments Com_k = a_k*Base8 to its polynomial
// coefficients, and every recipient checks its dealt share against them, so a dealer cannot hand out an
// inconsistent share undetected. Ported from threshold_compliance_poc.py (dkg Feldman check).

import {
  Point,
  IDENTITY,
  scalarMul,
  scalarBaseMul,
  pointAdd,
  pointEq,
  modSub,
} from "./bjj.js";

/** Commit to polynomial coefficients (low-to-high): Com_k = a_k * Base8. */
export function feldmanCommit(coeffs: bigint[]): Point[] {
  return coeffs.map((a) => scalarBaseMul(a));
}

/** Verify a dealt share f(i) against the dealer's commitments: f(i)*Base8 == sum_k (i^k) * Com_k. */
export function feldmanVerifyShare(
  i: bigint,
  share: bigint,
  commitments: Point[],
): boolean {
  const lhs = scalarBaseMul(share);
  let rhs: Point = IDENTITY;
  let ipow = 1n;
  for (const com of commitments) {
    rhs = pointAdd(rhs, scalarMul(ipow, com));
    ipow = modSub(ipow * i);
  }
  return pointEq(lhs, rhs);
}
