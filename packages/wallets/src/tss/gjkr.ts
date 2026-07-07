// GJKR anti-bias distributed key generation over BabyJubJub (Gennaro-Jarecki-Krawczyk-Rabin, "Secure
// Distributed Key Generation for Discrete-Log Based Cryptosystems", J. Cryptology 2007, eprint 2006/xxxx).
// The plain Feldman DKG in dkg.ts is unbiased only if every dealer commits before seeing others: a rogue LAST
// dealer can abort after observing sum_i A_{i,0} and thereby bias the group key C. GJKR closes this with a
// two-phase commit. Phase 1 (Pedersen): dealers publish PERFECTLY-HIDING commitments C_{i,k} = a_{i,k}*Base8 +
// b_{i,k}*H over dual polynomials and deal dual shares (f_i(j), f'_i(j)); recipients verify and the QUAL set is
// FIXED here -- because C_{i,k} hides a_{i,0}, no dealer learns anything about the eventual group key while
// QUAL is decided, so none can bias by choosing to abort. Phase 2 (Feldman reveal): QUAL dealers reveal
// A_{i,k} = a_{i,k}*Base8 and everyone checks f_i(j)*Base8 == sum_k j^k A_{i,k}; C = sum over QUAL of A_{i,0}.
// The output (C, per-member a-shares, V) is byte-for-byte the same shape as the Feldman DKG, so it is a
// drop-in for the threshold-compliance toolkit; the b-polynomial is discarded after QUAL.

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

// BabyJubJub cofactor: order = 8 * SUBORDER, so 8*P lands in the prime-order subgroup for any curve point P.
const COFACTOR = 8n;

// Domain string seeding the nothing-up-my-sleeve derivation of H (<= 32 bytes; hashed via stringToFr).
const H_SEED_DOMAIN = "hisoka.tss.pedersen.h";

// Upper bound on the try-and-increment search; ~half of candidate y map to a valid x, so success is near-certain
// within a few tries and this bound is never approached in practice.
const H_MAX_TRIES = 256n;

/** Derive the second Pedersen generator H by hash-to-curve with UNKNOWN discrete log wrt Base8: seed a
 *  Poseidon2 counter chain from a domain string, interpret each output as a packed BabyJubJub point (unpackPoint
 *  does the modular sqrt), and cofactor-clear the first valid candidate into the prime-order subgroup. H is a
 *  public deterministic constant; nobody knows k such that H = k*Base8, which is what lets the phase-1
 *  commitments hide the secret. */
async function deriveH(): Promise<Point> {
  const seed = (await stringToFr(H_SEED_DOMAIN)).toBigInt();
  for (let ctr = 0n; ctr < H_MAX_TRIES; ctr++) {
    const candidate = await poseidon2([seed, ctr]);
    const unpacked = unpackPoint(candidate);
    if (unpacked === null) continue; // no x on the curve for this y -> try the next counter
    const h = scalarMul(COFACTOR, [unpacked[0], unpacked[1]]);
    if (isIdentity(h)) continue; // candidate sat in the order-8 torsion; cofactor-clearing killed it
    if (pointEq(h, BASE8)) continue; // H must be independent of the primary generator
    assertInSubgroup(h, "H"); // on-curve AND prime-order AND non-identity
    return h;
  }
  throw new Error(
    "gjkr: failed to derive H within the try-and-increment bound",
  );
}

// Memoized so deriveH's hash-to-curve loop runs at most once, ON FIRST USE -- never at module load (a
// top-level await would break the CJS build and force crypto work on any import of this file).
let hPromise: Promise<Point> | null = null;

/** The nothing-up-my-sleeve second generator for Pedersen commitments; prime-order, != identity, != Base8,
 *  with discrete log wrt Base8 unknown to all parties. Lazy + cached. */
export function getH(): Promise<Point> {
  if (hPromise === null) hPromise = deriveH();
  return hPromise;
}

/** Pedersen vector commitment to dual coefficient lists (low-to-high): C_k = a_k*Base8 + b_k*H. Perfectly hides
 *  the a-coefficients under H's unknown discrete log. */
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

/** Verify a dealt dual share against a dealer's Pedersen commitments:
 *  f(i)*Base8 + f'(i)*H == sum_k (i^k) * C_k. */
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

// A dealer's phase-1 state. aCoeffs/bCoeffs and the dealt shares are secret and MUST never be logged.
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

/** Drive a full GJKR DKG among `n` participants with threshold `t`. `faults.badShareDealers` corrupts a dealer's
 *  dealt Pedersen share so its phase-1 dual-share check fails at a recipient and it is dropped from QUAL. Returns
 *  the aggregated group key over the QUAL set fixed in phase 1. This is a reference driver: a real deployment
 *  replaces the loops with an authenticated echo-broadcast round (anti-equivocation) and, per GJKR, reconstructs
 *  rather than drops a QUAL dealer that later equivocates in the Feldman reveal (a QUAL dealer's contribution can
 *  never be removed post-QUAL without re-opening the bias window). */
export async function runGjkrDkg(
  n: number,
  t: number,
  context: bigint,
  faults?: { badShareDealers?: Set<bigint> },
): Promise<DkgResult> {
  const participants: bigint[] = [];
  for (let i = 1; i <= n; i++) participants.push(BigInt(i));

  // Phase 1: every dealer publishes Pedersen commitments and deals dual shares.
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

  // QUAL is FIXED here from the phase-1 dual-share check ONLY -- no Feldman/discrete-log data is consulted, so no
  // dealer can bias the group key by aborting.
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

  // Phase 2: QUAL dealers reveal Feldman commitments A_{i,k} = a_{i,k}*Base8 plus a PoP of a_{i,0}. An honest
  // reveal is consistent with the phase-1-verified a-shares; an inconsistent reveal would, in a real deployment,
  // trigger GJKR reconstruction (never removal from QUAL), so a failure here is an invariant violation.
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
