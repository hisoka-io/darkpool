// Multisig note VIEW layer. An account address is { ownerCommitment = Poseidon2(gpk), V = v*Base8 } where v is
// the shared viewing key every member holds (1-of-n viewing) and gpk is the FROST (t,n) signing key (t-of-n
// spend). OWNER and VIEW key are DECOUPLED: owner commits to gpk (spend authority), the note is
// discovered/decrypted via the account's viewing machinery keyed to V -- fusing them would re-lock members who
// hold only v (see MULTISIG-ACCOUNT-DESIGN sections 4-5). Three note flavours reuse the note-format KEM/DEM:
//   INCOMING (external sender -> account): sender picks eph; CEK = (eph*C).x; cek_wrap = CEK + Poseidon2((eph*
//     V).x); owner = Poseidon2(gpk); tag = V.x (STATIC per account, even-y). A member recovers CEK from v +
//     eph_pub via the ECDH symmetry (v*eph_pub).x == (eph*V).x, no eph needed.
//   SELF/change (the quorum's own outputs): the coordinating member derives eph from a MEMBER-PARTITIONED
//     sub-sequence keyed by (v, member_id, j); tag = eph_pub.x; NO wrap -- a member re-derives eph and takes
//     CEK = (eph*C).x directly (C is public). Disjoint per-member sub-sequences + a durable per-member counter
//     make eph collision-free with no cross-coordinator lock, preserving single-shot Raven precompute.
//   DEPOSIT self-funding: a FRESH CSPRNG eph (deposits are one-shot and public; no v-derivation needed).
// Compliance recovers CEK = (c*eph_pub).x uniformly for all (handled by the threshold toolkit).

import { Fr } from "@aztec/foundation/fields";
import { Point, scalarBaseMul, randScalar } from "../tss/bjj.js";
import { deriveCek, wrapCek, unwrapCek } from "../crypto/kem.js";
import { Kdf } from "../crypto/Kdf.js";
import { toBjjScalar } from "../crypto/index.js";
import { Poseidon } from "../crypto/Poseidon.js";
import { isEvenY } from "../note/keys.js";
import { multisigOwner } from "./message.js";

/** note_type set (STANDARD=0, MULTISIG=1); CONDITIONAL=2 is reserved and not enabled. Matches the circuit. */
export const NOTE_TYPE_STANDARD = 0n;
export const NOTE_TYPE_MULTISIG = 1n;

// eph_{m,j} = toBjj(KDF("hisoka.msSelfEph", v, Poseidon2(member_id, j))). Folds the SECRET v so eph is never
// publicly derivable (CEK = (eph*C).x would otherwise be computable by anyone); member_id partitions a
// disjoint sub-sequence per member; j is that member's durable single-writer counter.
const SELF_EPH_LABEL = "hisoka.msSelfEph";

// A discovery tag is a point's .x, which aliases (x, +/-y); only even-y points give an injective tag. This
// rejection-sampling bound (each candidate is even-y with prob ~1/2) only guards a non-terminating loop.
const MAX_INDEX_ROLL = 256n;

/** The public multisig account address a sender uses: owner fixes t-of-n spending, V fixes 1-of-n viewing. */
export interface MultisigAddress {
  /** Poseidon2(gpk.x, gpk.y) -- the note owner commitment. */
  ownerCommitment: Fr;
  /** V = v*Base8, the shared viewing key's public point; even-y canonical (its .x is the static incoming tag). */
  viewPub: Point;
}

// V's parity is fixed by v, so the account ceremony MUST choose v so V is even-y (unsafe-sim establishViewKey
// re-runs the reveal round until it is); an odd-y V is rejected here rather than silently aliased.
function assertEvenYViewPub(viewPub: Point): void {
  if (!isEvenY(viewPub)) {
    throw new Error("multisig view key V has a non-canonical odd y");
  }
}

/** Account address from the FROST signing key gpk and the shared viewing scalar v. */
export async function multisigAddress(
  gpk: Point,
  v: Fr,
): Promise<MultisigAddress> {
  const ownerCommitment = new Fr(await multisigOwner(gpk));
  const viewPub = scalarBaseMul(v.toBigInt());
  assertEvenYViewPub(viewPub);
  return { ownerCommitment, viewPub };
}

/** An incoming note wrapped to the account: owner commits to gpk, CEK is wrapped to the shared V. */
export interface IncomingMultisigNote {
  /** Poseidon2(gpk) -- spend authority, decoupled from the view key. */
  owner: Fr;
  cek: Fr;
  /** CEK wrapped to V; a member recovers it with v + eph_pub. */
  cekWrap: Fr;
  /** V.x -- the static account discovery tag. */
  tag: Fr;
  ephPub: Point;
}

/** Sender side of an INCOMING note: owner = Poseidon2(gpk), CEK wrapped to V, tag = V.x (decoupled owner/view). */
export async function buildIncomingMultisigNote(
  eph: Fr,
  compliancePk: Point,
  gpk: Point,
  viewPub: Point,
): Promise<IncomingMultisigNote> {
  assertEvenYViewPub(viewPub);
  const owner = new Fr(await multisigOwner(gpk));
  const cek = deriveCek(eph, compliancePk);
  const cekWrap = await wrapCek(cek, eph, viewPub);
  return {
    owner,
    cek,
    cekWrap,
    tag: new Fr(viewPub[0]),
    ephPub: scalarBaseMul(eph.toBigInt()),
  };
}

/** Member side of an INCOMING note: recover CEK from the shared v and the on-chain eph_pub (no eph). */
export async function memberReadIncoming(
  cekWrap: Fr,
  v: Fr,
  ephPub: Point,
): Promise<Fr> {
  return unwrapCek(cekWrap, v, ephPub);
}

// The member-partitioned salt Poseidon2(member_id, j): disjoint per member, monotone per member's counter.
async function memberSalt(memberId: bigint, j: bigint): Promise<Fr> {
  return Poseidon.hash([new Fr(memberId), new Fr(j)]);
}

/** Member-partitioned self/change ephemeral eph_{m,j}, deterministic from the shared v so every member
 *  re-derives it. Different member_id or j -> different eph (disjoint sub-sequences). eph is SECRET (folds v). */
export async function deriveSelfEph(
  v: Fr,
  memberId: bigint,
  j: bigint,
): Promise<{ eph: Fr; ephPub: Point }> {
  const salt = await memberSalt(memberId, j);
  const eph = toBjjScalar(await Kdf.derive(SELF_EPH_LABEL, v, salt));
  return { eph, ephPub: scalarBaseMul(eph.toBigInt()) };
}

/** The next even-y self/change tag for member `memberId` from their durable counter `startJ` (rolls j until
 *  eph_pub is even-y, mirroring the single-wallet self-tag roll). The returned `j` is the counter to persist. */
export interface CanonicalMultisigSelfTag {
  eph: Fr;
  ephPub: Point;
  j: bigint;
  tag: Fr;
}
export async function canonicalMultisigSelfTag(
  v: Fr,
  memberId: bigint,
  startJ: bigint,
): Promise<CanonicalMultisigSelfTag> {
  for (let attempt = 0n; attempt < MAX_INDEX_ROLL; attempt++) {
    const j = startJ + attempt;
    const { eph, ephPub } = await deriveSelfEph(v, memberId, j);
    if (isEvenY(ephPub)) {
      return { eph, ephPub, j, tag: new Fr(ephPub[0]) };
    }
  }
  throw new Error(
    `multisig: no even-y self ephemeral within ${MAX_INDEX_ROLL} of member ${memberId} from ${startJ}`,
  );
}

/** Coordinator side of a SELF/change note: CEK straight to compliance C, tag = eph_pub.x, no wrap. */
export interface SelfMultisigNote {
  cek: Fr;
  tag: Fr;
  ephPub: Point;
}
export function buildSelfNote(eph: Fr, compliancePk: Point): SelfMultisigNote {
  const cek = deriveCek(eph, compliancePk);
  const ephPub = scalarBaseMul(eph.toBigInt());
  return { cek, tag: new Fr(ephPub[0]), ephPub };
}

/** Member side of a SELF/change note: re-derive eph from (v, member_id, j), then CEK = (eph*C).x directly. */
export async function memberReadSelf(
  v: Fr,
  memberId: bigint,
  j: bigint,
  compliancePk: Point,
): Promise<Fr> {
  const { eph } = await deriveSelfEph(v, memberId, j);
  return deriveCek(eph, compliancePk);
}

/** A fresh CSPRNG even-y ephemeral for a self-funding multisig DEPOSIT (one-shot; deposit value/asset are
 *  public, and compliance decrypts via (c*eph_pub).x). Not v-derived, so not member-discoverable -- discovery
 *  of a self-funding deposit is by the public on-chain deposit, not the note. */
export async function freshMultisigDepositEph(): Promise<{
  eph: Fr;
  ephPub: Point;
  tag: Fr;
}> {
  for (let attempt = 0n; attempt < MAX_INDEX_ROLL; attempt++) {
    const eph = toBjjScalar(new Fr(randScalar()));
    const ephPub = scalarBaseMul(eph.toBigInt());
    if (isEvenY(ephPub)) return { eph, ephPub, tag: new Fr(ephPub[0]) };
  }
  throw new Error("multisig: no even-y fresh deposit ephemeral sampled");
}
