// Threshold-compliance decryption: a (t,n) committee recovers CEK = (c*eph_pub).x WITHOUT forming c
// (Lagrange-in-exponent over DLEQ-checked partials). Wraps to the RECIPIENT, so CEK = S.x uniformly.

import { Fr } from "@aztec/foundation/fields";
import {
  Point,
  IDENTITY,
  scalarMul,
  pointAdd,
  assertInSubgroup,
  inSubgroupNonId,
} from "../tss/bjj.js";
import { lagrangeAtZero } from "../tss/shamir.js";
import { cpProve, cpVerify, DleqProof } from "../tss/chaumPedersen.js";

export interface Partial {
  id: bigint;
  proof: DleqProof;
}

/** Subgroup-check `ephPub` FIRST (a low-order eph_pub leaks c_i via the cofactor). `share` secret; never log. */
export async function partialDecrypt(
  id: bigint,
  share: bigint,
  ephPub: Point,
): Promise<Partial> {
  assertInSubgroup(ephPub, "eph_pub");
  const proof = await cpProve(share, ephPub);
  return { id, proof };
}

export async function combine(
  ephPub: Point,
  partials: Partial[],
  V: ReadonlyMap<bigint, Point>,
  threshold: number,
): Promise<Point> {
  assertInSubgroup(ephPub, "eph_pub");
  const verified: { id: bigint; D: Point }[] = [];
  const seen = new Set<bigint>();
  for (const p of partials) {
    // Dedup by id BEFORE the count gate: one member's valid partial repeated must not fill the quorum.
    if (seen.has(p.id)) continue;
    const vi = V.get(p.id);
    if (vi === undefined) continue;
    if (!inSubgroupNonId(p.proof.D)) continue;
    if (!(await cpVerify(vi, ephPub, p.proof))) continue;
    seen.add(p.id);
    verified.push({ id: p.id, D: p.proof.D });
  }
  // Below t distinct partials Lagrange interpolates a WRONG value: fail loudly, not silently.
  if (verified.length < threshold)
    throw new Error(
      `compliance: ${verified.length} valid partials, need >= ${threshold}`,
    );
  const quorum = verified.map((v) => v.id);
  let S: Point = IDENTITY;
  for (const { id, D } of verified) {
    S = pointAdd(S, scalarMul(lagrangeAtZero(id, quorum), D));
  }
  return S;
}

export async function thresholdCek(
  ephPub: Point,
  partials: Partial[],
  V: ReadonlyMap<bigint, Point>,
  threshold: number,
): Promise<Fr> {
  const S = await combine(ephPub, partials, V, threshold);
  return new Fr(S[0]);
}

/** Keep the first t valid partials; list the invalid ones in `excluded` without failing the decrypt. */
export async function thresholdCekRobust(
  ephPub: Point,
  allPartials: Partial[],
  V: ReadonlyMap<bigint, Point>,
  t: number,
): Promise<{ cek: Fr; used: bigint[]; excluded: bigint[] }> {
  assertInSubgroup(ephPub, "eph_pub");
  const good: Partial[] = [];
  const excluded: bigint[] = [];
  const seen = new Set<bigint>();
  for (const p of allPartials) {
    if (seen.has(p.id)) continue;
    const vi = V.get(p.id);
    const ok =
      vi !== undefined &&
      inSubgroupNonId(p.proof.D) &&
      (await cpVerify(vi, ephPub, p.proof));
    if (ok) {
      seen.add(p.id);
      if (good.length < t) good.push(p);
    } else {
      excluded.push(p.id);
    }
  }
  if (good.length < t)
    throw new Error(
      `compliance: only ${good.length} valid partials, need ${t}`,
    );
  const cek = await thresholdCek(ephPub, good, V, t);
  return { cek, used: good.map((p) => p.id), excluded };
}
