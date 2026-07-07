// No-trusted-dealer Feldman DKG over BabyJubJub with a Schnorr PoP (rogue-key defense). c (= sum of the
// dealers' secrets) is never assembled by any party. Ported from threshold_compliance_poc.py (dkg).

import {
  Point,
  IDENTITY,
  scalarBaseMul,
  scalarMul,
  pointAdd,
  pointEq,
  modSub,
  randScalar,
} from "./bjj.js";
import { polyEval } from "./shamir.js";
import { feldmanCommit, feldmanVerifyShare } from "./vss.js";
import { hashToScalar } from "./hashToScalar.js";
import { FROST_POP_DOMAIN } from "./domains.js";

/** Bound to the prover id + a context field so a rogue dealer cannot replay another party's PoP. */
export interface SchnorrPoP {
  R: Point;
  z: bigint;
}

export interface DealerContribution {
  id: bigint;
  commitments: Point[];
  pop: SchnorrPoP;
  shares: ReadonlyMap<bigint, bigint>;
}

async function popChallenge(
  id: bigint,
  context: bigint,
  com0: Point,
  R: Point,
): Promise<bigint> {
  return hashToScalar(FROST_POP_DOMAIN, [
    id,
    context,
    com0[0],
    com0[1],
    R[0],
    R[1],
  ]);
}

export async function provePoP(
  id: bigint,
  context: bigint,
  secret: bigint,
  commitment: Point,
): Promise<SchnorrPoP> {
  const k = randScalar();
  const R = scalarBaseMul(k);
  const e = await popChallenge(id, context, commitment, R);
  const z = modSub(k + e * secret);
  return { R, z };
}

export async function verifyPoP(
  id: bigint,
  context: bigint,
  commitments: Point[],
  pop: SchnorrPoP,
): Promise<boolean> {
  const com0 = commitments[0];
  const e = await popChallenge(id, context, com0, pop.R);
  const lhs = scalarBaseMul(pop.z);
  const rhs = pointAdd(pop.R, scalarMul(e, com0));
  return pointEq(lhs, rhs);
}

export async function dealerContribute(
  id: bigint,
  participants: bigint[],
  t: number,
  context: bigint,
): Promise<{ contribution: DealerContribution; secret: bigint }> {
  const coeffs: bigint[] = [];
  for (let k = 0; k < t; k++) coeffs.push(randScalar());
  const commitments = feldmanCommit(coeffs);
  const shares = new Map<bigint, bigint>();
  for (const j of participants) shares.set(j, polyEval(coeffs, j));
  const pop = await provePoP(id, context, coeffs[0], commitments[0]);
  return { contribution: { id, commitments, pop, shares }, secret: coeffs[0] };
}

export async function verifyContribution(
  recipientId: bigint,
  contribution: DealerContribution,
  context: bigint,
): Promise<boolean> {
  if (contribution.commitments.length === 0) return false;
  const share = contribution.shares.get(recipientId);
  if (share === undefined) return false;
  if (!feldmanVerifyShare(recipientId, share, contribution.commitments))
    return false;
  return verifyPoP(
    contribution.id,
    context,
    contribution.commitments,
    contribution.pop,
  );
}

export interface DkgResult {
  C: Point;
  /** Per-member aggregate share c_i; NEVER logged. */
  shares: Map<bigint, bigint>;
  V: Map<bigint, Point>;
  qual: bigint[];
}

export function aggregate(
  participants: bigint[],
  qualContributions: DealerContribution[],
): DkgResult {
  let C: Point = IDENTITY;
  for (const c of qualContributions) C = pointAdd(C, c.commitments[0]);
  const shares = new Map<bigint, bigint>();
  const V = new Map<bigint, Point>();
  for (const i of participants) {
    let ci = 0n;
    for (const c of qualContributions) {
      const s = c.shares.get(i);
      if (s === undefined)
        throw new Error(`dkg: QUAL dealer ${c.id} missing share for ${i}`);
      ci = modSub(ci + s);
    }
    shares.set(i, ci);
    V.set(i, scalarBaseMul(ci));
  }
  return { C, shares, V, qual: qualContributions.map((c) => c.id) };
}
