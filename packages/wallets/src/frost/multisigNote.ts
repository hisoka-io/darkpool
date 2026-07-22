// Multisig note VIEW layer. Owner=Poseidon2(gpk) (spend) is DECOUPLED from view key V=v*Base8. Self eph folds
// SECRET v partitioned by (v, member_id, j) so it is not publicly derivable and per-member sequences never collide.
// Discovery tags are point.x, so V and every eph_pub must be even-y.

import { Fr } from "@aztec/foundation/fields";
import { Point, scalarBaseMul, randScalar } from "../tss/bjj.js";
import { deriveCek, wrapCek, unwrapCek } from "../crypto/kem.js";
import { Kdf } from "../crypto/Kdf.js";
import { toBjjScalar } from "../crypto/index.js";
import { Poseidon } from "../crypto/Poseidon.js";
import { isEvenY } from "../note/keys.js";
import { multisigOwner } from "./message.js";

/** note_type set; MUST match the circuit (STANDARD=0, MULTISIG=1; CONDITIONAL=2 reserved). */
export const NOTE_TYPE_STANDARD = 0n;
export const NOTE_TYPE_MULTISIG = 1n;

const SELF_EPH_LABEL = "hisoka.msSelfEph";

const MAX_INDEX_ROLL = 256n;

export interface MultisigAddress {
  ownerCommitment: Fr;
  viewPub: Point;
}

function assertEvenYViewPub(viewPub: Point): void {
  if (!isEvenY(viewPub)) {
    throw new Error("multisig view key V has a non-canonical odd y");
  }
}

export async function multisigAddress(
  gpk: Point,
  v: Fr,
): Promise<MultisigAddress> {
  const ownerCommitment = new Fr(await multisigOwner(gpk));
  const viewPub = scalarBaseMul(v.toBigInt());
  assertEvenYViewPub(viewPub);
  return { ownerCommitment, viewPub };
}

export interface IncomingMultisigNote {
  owner: Fr;
  cek: Fr;
  cekWrap: Fr;
  tag: Fr;
  ephPub: Point;
}

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

export async function memberReadIncoming(
  cekWrap: Fr,
  v: Fr,
  ephPub: Point,
): Promise<Fr> {
  return unwrapCek(cekWrap, v, ephPub);
}

async function memberSalt(memberId: bigint, j: bigint): Promise<Fr> {
  return Poseidon.hash([new Fr(memberId), new Fr(j)]);
}

export async function deriveSelfEph(
  v: Fr,
  memberId: bigint,
  j: bigint,
): Promise<{ eph: Fr; ephPub: Point }> {
  const salt = await memberSalt(memberId, j);
  const eph = toBjjScalar(await Kdf.derive(SELF_EPH_LABEL, v, salt));
  return { eph, ephPub: scalarBaseMul(eph.toBigInt()) };
}

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

export async function memberReadSelf(
  v: Fr,
  memberId: bigint,
  j: bigint,
  compliancePk: Point,
): Promise<Fr> {
  const { eph } = await deriveSelfEph(v, memberId, j);
  return deriveCek(eph, compliancePk);
}

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
