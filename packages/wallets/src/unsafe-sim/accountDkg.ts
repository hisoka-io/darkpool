// SIMULATED FROST multisig ACCOUNT ceremony. An account has two keys established at one ceremony:
//   - gpk: the (t,n) FROST signing key (t-of-n spend authority), via the shared PedPoP DKG (tss/dkg).
//   - v:   a SHARED viewing key every member holds in plaintext (1-of-n viewing; NOT Shamir-shared). It is
//          established by a commit-reveal so no single member biases it and all members learn the same value;
//          an observer sees only hiding commitments. V = v*Base8. owner = Poseidon2(gpk.x, gpk.y).
// This driver manufactures all n signing shares + the shared v in ONE process, so it is a TEST/DEV reference
// ONLY and MUST NOT ship (advertising it as t-of-n custody would be a silent 1-of-1). The production account
// ceremony (authenticated echo-broadcast for a single commitment view + complaint round + GJKR
// reconstruct-not-drop + a PoP binding the peer commitment set) is a required pre-mainnet gate, unbuilt here.

import { Fr } from "@aztec/foundation/fields";
import { Point, scalarBaseMul, modSub, randScalar } from "../tss/bjj.js";
import { poseidon2 } from "../tss/hashToScalar.js";
import { Poseidon } from "../crypto/Poseidon.js";
import { isEvenY } from "../note/keys.js";
import { runDkg } from "./dkg.js";
import type { DkgResult } from "../tss/dkg.js";

// The shared viewing point V.x is the STATIC Raven discovery tag; .x aliases +/-y, so only an even-y V is an
// injective tag. v is a fixed commit-reveal sum, so it cannot be rolled to even-y AFTER the fact -- the reveal
// round is re-run until the summed V is even-y. This bound only guards a non-terminating loop (~1/2 per round).
const MAX_VIEWKEY_ROUNDS = 256;

export interface FrostAccount {
  /** t-of-n signing key. */
  gpk: Point;
  /** Per-member signing shares (secret). */
  shares: Map<bigint, bigint>;
  /** Per-member verification keys V_i = share_i*Base8. */
  verificationKeys: Map<bigint, Point>;
  /** Shared viewing key held by EVERY member (secret; never log). */
  viewKey: bigint;
  /** Public viewing key V = v*Base8 (part of the account address; even-y canonical). */
  viewPub: Point;
  /** Note owner commitment = Poseidon2(gpk.x, gpk.y). */
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

/** Establish the shared viewing key by commit-reveal (each member commits Poseidon2([v_i, blind_i]) then
 *  reveals; a mismatched reveal is rejected; v = sum(v_i) mod SUBORDER), re-running the round until V is
 *  even-y. Simulated here (a real ceremony runs the rounds over the authenticated channel). */
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

/** Run a full FROST account ceremony among n members with threshold t. */
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
