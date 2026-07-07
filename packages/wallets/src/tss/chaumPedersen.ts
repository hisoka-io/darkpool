// Chaum-Pedersen DLEQ proof that a partial D = secret*epk was formed with the SAME secret whose public key
// is V = secret*Base8, i.e. log_Base8(V) == log_epk(D). A committee member proves this over its share so a
// combiner can reject a random/forged partial. Ported from threshold_compliance_poc.py (cp_prove/cp_verify),
// with the Fiat-Shamir hash swapped from the PoC's SHA-256 stand-in to the real Poseidon2 (CP_DOMAIN).

import {
  Point,
  BASE8,
  scalarMul,
  pointAdd,
  pointEq,
  modSub,
  randScalar,
  inSubgroupNonId,
} from "./bjj.js";
import { hashToScalar } from "./hashToScalar.js";
import { CP_DOMAIN } from "./domains.js";

export interface DleqProof {
  D: Point;
  A: Point;
  B: Point;
  z: bigint;
}

function transcript(
  epk: Point,
  V: Point,
  D: Point,
  A: Point,
  B: Point,
): bigint[] {
  return [
    BASE8[0],
    BASE8[1],
    epk[0],
    epk[1],
    V[0],
    V[1],
    D[0],
    D[1],
    A[0],
    A[1],
    B[0],
    B[1],
  ];
}

/** Prove D = secret*epk with V = secret*Base8. `secret` is a share; never log it. */
export async function cpProve(secret: bigint, epk: Point): Promise<DleqProof> {
  const V = scalarMul(secret, BASE8);
  const D = scalarMul(secret, epk);
  const k = randScalar();
  const A = scalarMul(k, BASE8);
  const B = scalarMul(k, epk);
  const e = await hashToScalar(CP_DOMAIN, transcript(epk, V, D, A, B));
  const z = modSub(k + e * secret);
  return { D, A, B, z };
}

/** Verify a DLEQ proof against the member's registered V. Subgroup-checks D before trusting it, so a
 *  small-order partial cannot slip a cofactor leak past the combiner. */
export async function cpVerify(
  V: Point,
  epk: Point,
  proof: DleqProof,
): Promise<boolean> {
  if (!inSubgroupNonId(proof.D)) return false;
  const e = await hashToScalar(
    CP_DOMAIN,
    transcript(epk, V, proof.D, proof.A, proof.B),
  );
  const lhsBase = scalarMul(proof.z, BASE8);
  const rhsBase = pointAdd(proof.A, scalarMul(e, V));
  const lhsEpk = scalarMul(proof.z, epk);
  const rhsEpk = pointAdd(proof.B, scalarMul(e, proof.D));
  return pointEq(lhsBase, rhsBase) && pointEq(lhsEpk, rhsEpk);
}
