// SIMULATED single-process DKG driver. Every dealer's share is built in ONE machine's RAM, so this driver
// holds all n secrets at once -- it is a TEST/DEV reference ONLY and MUST NOT ship. A production account or
// committee ceremony runs the tss/dkg primitives (dealerContribute / verifyContribution / aggregate) over an
// authenticated echo-broadcast round (one shared commitment view = anti-equivocation) + a complaint round +
// GJKR reconstruct-not-drop for post-QUAL equivocation, with the PoP binding the peer commitment set. That
// networked ceremony is a required pre-mainnet gate, unbuilt here. Kept out of every shipped barrel.

import { modSub } from "../tss/bjj.js";
import {
  DealerContribution,
  DkgResult,
  dealerContribute,
  verifyContribution,
  aggregate,
} from "../tss/dkg.js";

/** Drive a full DKG among `n` participants with threshold `t`. Faults let a test inject a bad dealer (whose
 *  contribution fails verification and is disqualified from QUAL). Returns the aggregated group key over the
 *  honest QUAL set. Simulated single-loop: a real deployment replaces the loop with the authenticated
 *  echo-broadcast ceremony above. */
export async function runDkg(
  n: number,
  t: number,
  context: bigint,
  faults?: { badShareDealers?: Set<bigint>; badPopDealers?: Set<bigint> },
): Promise<DkgResult> {
  const participants: bigint[] = [];
  for (let i = 1; i <= n; i++) participants.push(BigInt(i));

  const contributions: DealerContribution[] = [];
  for (const id of participants) {
    const { contribution } = await dealerContribute(
      id,
      participants,
      t,
      context,
    );
    let c = contribution;
    if (faults?.badShareDealers?.has(id)) {
      // Corrupt one dealt share so its Feldman check fails at that recipient.
      const bad = new Map(c.shares);
      const victim = participants.find((p) => p !== id) ?? id;
      bad.set(victim, modSub((bad.get(victim) ?? 0n) + 1n));
      c = { ...c, shares: bad };
    }
    if (faults?.badPopDealers?.has(id)) {
      c = { ...c, pop: { R: c.pop.R, z: modSub(c.pop.z + 1n) } };
    }
    contributions.push(c);
  }

  // Every participant verifies every dealer; a dealer any honest participant complains about is disqualified.
  const qual: DealerContribution[] = [];
  for (const c of contributions) {
    let ok = true;
    for (const j of participants) {
      if (!(await verifyContribution(j, c, context))) {
        ok = false;
        break;
      }
    }
    if (ok) qual.push(c);
  }
  if (qual.length === 0) throw new Error("dkg: no qualified dealers");
  return aggregate(participants, qual);
}
