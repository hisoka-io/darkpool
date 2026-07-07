// GJKR anti-bias DKG over BabyJubJub (Gennaro-Jarecki-Krawczyk-Rabin, "Secure Distributed Key Generation for
// Discrete-Log Based Cryptosystems", J. Cryptology 2007). A two-phase commit closes the last-dealer bias in
// the plain Feldman DKG (dkg.ts): phase 1 FIXES QUAL from perfectly-hiding Pedersen commitments alone, so no
// dealer learns anything about C while QUAL is decided; phase 2 reveals Feldman and sets C. Drop-in output.

import { unpackPoint } from "@zk-kit/baby-jubjub";
import {
  Point,
  BASE8,
  IDENTITY,
  scalarMul,
  scalarBaseMul,
  pointAdd,
  pointEq,
  isIdentity,
  assertInSubgroup,
  modSub,
  randScalar,
} from "./bjj.js";
import { polyEval } from "./shamir.js";
import { feldmanCommit, feldmanVerifyShare } from "./vss.js";
import { poseidon2 } from "./hashToScalar.js";
import { stringToFr } from "../crypto/fields.js";
import {
  DealerContribution,
  DkgResult,
  provePoP,
  verifyPoP,
  aggregate,
} from "./dkg.js";

const COFACTOR = 8n;

const H_SEED_DOMAIN = "hisoka.tss.pedersen.h";

const H_MAX_TRIES = 256n;

/** Nothing-up-my-sleeve second Pedersen generator H with discrete log wrt Base8 unknown to all parties,
 *  which is what lets the phase-1 commitments hide the secret. */
async function deriveH(): Promise<Point> {
  const seed = (await stringToFr(H_SEED_DOMAIN)).toBigInt();
  for (let ctr = 0n; ctr < H_MAX_TRIES; ctr++) {
    const candidate = await poseidon2([seed, ctr]);
    const unpacked = unpackPoint(candidate);
    if (unpacked === null) continue;
    const h = scalarMul(COFACTOR, [unpacked[0], unpacked[1]]);
    if (isIdentity(h)) continue;
    if (pointEq(h, BASE8)) continue; // H must be independent of the primary generator
    assertInSubgroup(h, "H");
    return h;
  }
  throw new Error(
    "gjkr: failed to derive H within the try-and-increment bound",
  );
}

// Lazy, not module-load: a top-level await breaks the CJS build.
let hPromise: Promise<Point> | null = null;

export function getH(): Promise<Point> {
  if (hPromise === null) hPromise = deriveH();
  return hPromise;
}

export async function pedersenCommit(
  aCoeffs: bigint[],
  bCoeffs: bigint[],
): Promise<Point[]> {
  if (aCoeffs.length !== bCoeffs.length)
    throw new Error(
      `gjkr: Pedersen coefficient length mismatch (a=${aCoeffs.length}, b=${bCoeffs.length})`,
    );
  const h = await getH();
  return aCoeffs.map((a, k) =>
    pointAdd(scalarBaseMul(a), scalarMul(bCoeffs[k], h)),
  );
}

export async function pedersenVerifyShare(
  id: bigint,
  fShare: bigint,
  fPrimeShare: bigint,
  commitments: Point[],
): Promise<boolean> {
  const h = await getH();
  const lhs = pointAdd(scalarBaseMul(fShare), scalarMul(fPrimeShare, h));
  let rhs: Point = IDENTITY;
  let ipow = 1n;
  for (const com of commitments) {
    rhs = pointAdd(rhs, scalarMul(ipow, com));
    ipow = modSub(ipow * id);
  }
  return pointEq(lhs, rhs);
}

// aCoeffs/bCoeffs and the dealt shares are secret; never log.
interface PedersenDealer {
  id: bigint;
  aCoeffs: bigint[];
  bCoeffs: bigint[];
  commitments: Point[];
  aShares: Map<bigint, bigint>;
  fPrimeShares: Map<bigint, bigint>;
}

async function contribute(
  id: bigint,
  participants: bigint[],
  t: number,
): Promise<PedersenDealer> {
  const aCoeffs: bigint[] = [];
  const bCoeffs: bigint[] = [];
  for (let k = 0; k < t; k++) {
    aCoeffs.push(randScalar());
    bCoeffs.push(randScalar());
  }
  const commitments = await pedersenCommit(aCoeffs, bCoeffs);
  const aShares = new Map<bigint, bigint>();
  const fPrimeShares = new Map<bigint, bigint>();
  for (const j of participants) {
    aShares.set(j, polyEval(aCoeffs, j));
    fPrimeShares.set(j, polyEval(bCoeffs, j));
  }
  return { id, aCoeffs, bCoeffs, commitments, aShares, fPrimeShares };
}

/** Reference driver; a real deployment RECONSTRUCTS rather than drops a QUAL dealer that later equivocates
 *  (removing one post-QUAL re-opens the bias window). */
export async function runGjkrDkg(
  n: number,
  t: number,
  context: bigint,
  faults?: { badShareDealers?: Set<bigint> },
): Promise<DkgResult> {
  const participants: bigint[] = [];
  for (let i = 1; i <= n; i++) participants.push(BigInt(i));

  const dealers: PedersenDealer[] = [];
  for (const id of participants) {
    const dealer = await contribute(id, participants, t);
    if (faults?.badShareDealers?.has(id)) {
      const victim = participants.find((p) => p !== id) ?? id;
      const corrupted = (dealer.aShares.get(victim) ?? 0n) + 1n;
      dealer.aShares.set(victim, modSub(corrupted));
    }
    dealers.push(dealer);
  }

  // QUAL is fixed from the dual-share check ONLY (no discrete-log data), so no dealer can bias C by aborting.
  const qual: PedersenDealer[] = [];
  for (const dealer of dealers) {
    let ok = true;
    for (const j of participants) {
      const f = dealer.aShares.get(j);
      const fPrime = dealer.fPrimeShares.get(j);
      if (
        f === undefined ||
        fPrime === undefined ||
        !(await pedersenVerifyShare(j, f, fPrime, dealer.commitments))
      ) {
        ok = false;
        break;
      }
    }
    if (ok) qual.push(dealer);
  }
  if (qual.length === 0) throw new Error("gjkr: no qualified dealers");

  // An inconsistent reveal would trigger GJKR reconstruction (never QUAL removal): an invariant violation here.
  const qualContributions: DealerContribution[] = [];
  for (const dealer of qual) {
    const commitments = feldmanCommit(dealer.aCoeffs);
    const pop = await provePoP(
      dealer.id,
      context,
      dealer.aCoeffs[0],
      commitments[0],
    );
    for (const j of participants) {
      const f = dealer.aShares.get(j);
      if (f === undefined || !feldmanVerifyShare(j, f, commitments))
        throw new Error(
          `gjkr: Feldman reveal inconsistent for dealer ${dealer.id}`,
        );
    }
    if (!(await verifyPoP(dealer.id, context, commitments, pop)))
      throw new Error(`gjkr: PoP failed for QUAL dealer ${dealer.id}`);
    qualContributions.push({
      id: dealer.id,
      commitments,
      pop,
      shares: dealer.aShares,
    });
  }

  return aggregate(participants, qualContributions);
}
