// Threshold-compliance decryption: a (t,n) committee recovers CEK = (c*eph_pub).x for any note WITHOUT ever
// forming the compliance secret c. Each member returns a partial D_i = c_i*eph_pub plus a Chaum-Pedersen DLEQ
// proving it used its registered share; the (untrusted) combiner verifies the proofs and Lagrange-interpolates
// IN THE EXPONENT to S = c*eph_pub. Ported from threshold_compliance_poc.py (threshold_point) with the KEM
// correction: the frozen format wraps to the RECIPIENT, so compliance decrypts UNIFORMLY (CEK = S.x) for both
// self and incoming notes -- there is NO wrap_C unwrap in the compliance path.

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

/** A committee member's partial decryption of one ephemeral public key. */
export interface Partial {
  id: bigint;
  proof: DleqProof;
}

/** Member `id` (holding share c_i) partial-decrypts `ephPub`: subgroup-check the target FIRST (a low-order
 *  eph_pub would leak c_i via the cofactor), then return D_i = c_i*eph_pub with a DLEQ proof. `share` is
 *  secret; never log it. */
export async function partialDecrypt(
  id: bigint,
  share: bigint,
  ephPub: Point,
): Promise<Partial> {
  assertInSubgroup(ephPub, "eph_pub");
  const proof = await cpProve(share, ephPub);
  return { id, proof };
}

/** Combine >= t verified partials into S = c*eph_pub via Lagrange-in-exponent (mod SUBORDER). Rejects any
 *  partial whose DLEQ proof fails or whose D_i is not a prime-order point; throws if fewer than the quorum
 *  verify. The `V` map holds each member's public verification key V_i = c_i*Base8. */
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
    // Dedup by id BEFORE the count gate: one member submitting a valid partial t times must NOT satisfy the
    // quorum (it interpolates a wrong key, no leak but a silent wrong decrypt). Distinct ids only.
    if (seen.has(p.id)) continue;
    const vi = V.get(p.id);
    if (vi === undefined) continue;
    if (!inSubgroupNonId(p.proof.D)) continue;
    if (!(await cpVerify(vi, ephPub, p.proof))) continue;
    seen.add(p.id);
    verified.push({ id: p.id, D: p.proof.D });
  }
  // Below t DISTINCT valid partials, Lagrange over the smaller set interpolates a WRONG value (a degree-(t-1)
  // sharing is underdetermined by < t points): fail loudly instead of returning garbage.
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

/** The uniform compliance content-encryption key: CEK = S.x = (c*eph_pub).x, identical for self and incoming
 *  notes (the format wraps to the recipient, not to C). `threshold` is the sharing's t; combining fewer than
 *  t verified partials throws rather than returning a wrong key. */
export async function thresholdCek(
  ephPub: Point,
  partials: Partial[],
  V: ReadonlyMap<bigint, Point>,
  threshold: number,
): Promise<Fr> {
  const S = await combine(ephPub, partials, V, threshold);
  return new Fr(S[0]);
}

/** Robust combine: given all members' partials (some possibly malicious), keep the first `t` that verify and
 *  combine those. Excludes and attributes poisoned partials without failing the decrypt. */
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
    // One partial per id BEFORE the count gate: a duplicate valid partial must not fill the quorum twice.
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
