// Shared no-trusted-dealer DKG over BabyJubJub: each participant deals a Feldman-committed random polynomial,
// proves knowledge of its constant term (Schnorr PoP -- the rogue-key defense), and everyone verifies every
// received share against the public commitments. A dealer whose share fails Feldman or whose PoP is invalid
// is DISQUALIFIED; the group key and per-member shares are summed over the QUAL set only. `c` (= sum of the
// dealers' secrets) is never assembled by any party. Ported from threshold_compliance_poc.py (dkg), plus the
// PoP + complaint/QUAL round the PoC omits. Compliance (Part B) and FROST (Part C) both build on this.

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

/** Schnorr proof of knowledge of the discrete log of a commitment, bound to the prover identifier + a
 *  context field so a rogue dealer cannot replay another party's PoP. */
export interface SchnorrPoP {
  R: Point;
  z: bigint;
}

/** A dealer's round-1 output: public Feldman commitments + PoP (broadcast), and the private per-recipient
 *  shares (in a real deployment each is sent over an authenticated channel to that recipient only). */
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

/** Prove knowledge of `secret` where commitment = secret*Base8. */
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

/** Verify a PoP against the dealer's constant-term commitment (commitments[0]). */
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

/** A dealer computes its contribution: a random degree t-1 polynomial (constant term = its secret share of
 *  the group key), Feldman commitments, a PoP, and the dealt shares for every participant. */
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

/** A recipient verifies a dealer's contribution: its own dealt share against the Feldman commitments AND the
 *  dealer's PoP. Returns false (a complaint) if either fails. */
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
  /** The group public key C = sum over QUAL of the dealers' constant-term commitments. */
  C: Point;
  /** Per-member aggregate share c_i (= sum over QUAL of f_m(i)). NEVER logged. */
  shares: Map<bigint, bigint>;
  /** Public verification keys V_i = c_i*Base8. */
  V: Map<bigint, Point>;
  /** The qualified dealer identifiers. */
  qual: bigint[];
}

/** Aggregate the QUAL dealers' contributions into the group key + per-member shares/verification keys. */
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
