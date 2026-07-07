// SIMULATED single-process DKG driver: holds all n secrets in one process. TEST/DEV ONLY, MUST NOT ship.

import { modSub } from "../tss/bjj.js";
import {
  DealerContribution,
  DkgResult,
  dealerContribute,
  verifyContribution,
  aggregate,
} from "../tss/dkg.js";

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
