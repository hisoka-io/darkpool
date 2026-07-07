// BabyJubJub point + scalar helpers for the (t,n) primitives. Scalars live mod SUBORDER (the prime subgroup
// order), NEVER mod BN254 Fr -- mixing the moduli silently corrupts every Shamir/Lagrange result. Point ops
// delegate to @zk-kit/baby-jubjub; the subgroup guard mirrors in-circuit mint::assert_valid_compliance_pk.
// bigint arithmetic is not constant-time and cannot be zeroized: this is off-chain tooling, secrets (shares,
// nonces, c_i, v) rely on process isolation and MUST never be logged.

import {
  Base8,
  addPoint,
  mulPointEscalar,
  inCurve,
  subOrder,
} from "@zk-kit/baby-jubjub";

export type Point = [bigint, bigint];

export const SUBORDER: bigint = subOrder;

export const BASE8: Point = [Base8[0], Base8[1]];

export const IDENTITY: Point = [0n, 1n];

export function modSub(x: bigint): bigint {
  return ((x % SUBORDER) + SUBORDER) % SUBORDER;
}

function powSub(base: bigint, exp: bigint): bigint {
  let result = 1n;
  let b = modSub(base);
  let e = exp;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % SUBORDER;
    b = (b * b) % SUBORDER;
    e >>= 1n;
  }
  return result;
}

export function invSub(x: bigint): bigint {
  const r = modSub(x);
  if (r === 0n) throw new Error("tss: inverse of zero mod SUBORDER");
  return powSub(r, SUBORDER - 2n);
}

export function scalarMul(k: bigint, p: Point): Point {
  const out = mulPointEscalar(p, modSub(k));
  return [out[0], out[1]];
}

export function scalarBaseMul(k: bigint): Point {
  return scalarMul(k, BASE8);
}

export function pointAdd(a: Point, b: Point): Point {
  const out = addPoint(a, b);
  return [out[0], out[1]];
}

export function pointNeg(p: Point): Point {
  return [modP(-p[0]), p[1]];
}

// BN254 base field modulus (BabyJubJub coordinate field; distinct from the scalar field SUBORDER).
const BN254_P =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;
function modP(x: bigint): bigint {
  return ((x % BN254_P) + BN254_P) % BN254_P;
}

export function pointEq(a: Point, b: Point): boolean {
  return a[0] === b[0] && a[1] === b[1];
}

export function isIdentity(p: Point): boolean {
  return p[0] === 0n && p[1] === 1n;
}

export function inSubgroup(p: Point): boolean {
  if (!inCurve(p)) return false;
  const o = mulPointEscalar(p, SUBORDER);
  return o[0] === 0n && o[1] === 1n;
}

/** Guard before ECDH/scalar-mul on an untrusted point, or a small-order point leaks a scalar. */
export function inSubgroupNonId(p: Point): boolean {
  return inSubgroup(p) && !isIdentity(p);
}

export function assertInSubgroup(p: Point, label: string): void {
  if (!inCurve(p))
    throw new Error(`tss: ${label} is not on the BabyJubJub curve`);
  if (isIdentity(p)) throw new Error(`tss: ${label} is the identity`);
  if (!inSubgroup(p))
    throw new Error(`tss: ${label} is not in the prime-order subgroup`);
}

/** Random non-zero scalar in [1, SUBORDER). Wide 384-bit sampling keeps the modular bias below 2^-128. */
export function randScalar(): bigint {
  const bytes = new Uint8Array(48);
  globalThis.crypto.getRandomValues(bytes);
  let acc = 0n;
  for (const b of bytes) acc = (acc << 8n) | BigInt(b);
  return (acc % (SUBORDER - 1n)) + 1n;
}
