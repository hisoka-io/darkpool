// Feldman VSS. Ported from threshold_compliance_poc.py.

import {
  Point,
  IDENTITY,
  scalarMul,
  scalarBaseMul,
  pointAdd,
  pointEq,
  modSub,
} from "./bjj.js";

export function feldmanCommit(coeffs: bigint[]): Point[] {
  return coeffs.map((a) => scalarBaseMul(a));
}

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
