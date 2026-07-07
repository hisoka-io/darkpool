// SIMULATED FROST multisig account ceremony: gpk (FROST signing key) + v (shared 1-of-n viewing key by
// commit-reveal). Builds all n shares + v in ONE process: TEST/DEV ONLY, MUST NOT ship (a silent 1-of-1).

import { Fr } from "@aztec/foundation/fields";
import { Point, scalarBaseMul, modSub, randScalar } from "../tss/bjj.js";
import { poseidon2 } from "../tss/hashToScalar.js";
import { Poseidon } from "../crypto/Poseidon.js";
import { isEvenY } from "../note/keys.js";
import { runDkg } from "./dkg.js";
import type { DkgResult } from "../tss/dkg.js";

// V.x is the discovery tag, so V must be even-y; v is a fixed sum, so the reveal round re-runs until it is.
const MAX_VIEWKEY_ROUNDS = 256;

export interface FrostAccount {
  gpk: Point;
  shares: Map<bigint, bigint>;
  verificationKeys: Map<bigint, Point>;
  /** Shared viewing key held by EVERY member (secret; never log). */
  viewKey: bigint;
  viewPub: Point;
  owner: Fr;
  qual: bigint[];
}

interface ViewContribution {
  id: bigint;
  commit: bigint;
  vi: bigint;
  blind: bigint;
}

async function revealRound(
  participants: bigint[],
): Promise<{ v: bigint; V: Point }> {
  const contributions: ViewContribution[] = [];
  for (const id of participants) {
    const vi = randScalar();
    const blind = randScalar();
    const commit = await poseidon2([vi, blind]);
    contributions.push({ id, commit, vi, blind });
  }
  let v = 0n;
  for (const c of contributions) {
    const check = await poseidon2([c.vi, c.blind]);
    if (check !== c.commit)
      throw new Error(`view-key: bad reveal from member ${c.id}`);
    v = modSub(v + c.vi);
  }
  return { v, V: scalarBaseMul(v) };
}

async function establishViewKey(
  participants: bigint[],
): Promise<{ v: bigint; V: Point }> {
  for (let round = 0; round < MAX_VIEWKEY_ROUNDS; round++) {
    const { v, V } = await revealRound(participants);
    if (isEvenY(V)) return { v, V };
  }
  throw new Error(
    `view-key: no even-y V within ${MAX_VIEWKEY_ROUNDS} reveal rounds`,
  );
}

export async function frostAccountDkg(
  n: number,
  t: number,
  context: bigint,
): Promise<FrostAccount> {
  const dkg: DkgResult = await runDkg(n, t, context);
  const participants = [...dkg.shares.keys()];
  const { v, V } = await establishViewKey(participants);
  const owner = await Poseidon.hash([new Fr(dkg.C[0]), new Fr(dkg.C[1])]);
  return {
    gpk: dkg.C,
    shares: dkg.shares,
    verificationKeys: dkg.V,
    viewKey: v,
    viewPub: V,
    owner,
    qual: dkg.qual,
  };
}
