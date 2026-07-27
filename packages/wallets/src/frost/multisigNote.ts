// owner=Poseidon2(gpk) is DECOUPLED from the view key V=v*Base8. Discovery tags are point.x, so V and every eph_pub must be even-y.

import { Fr } from "@aztec/foundation/fields";
import { Point, scalarBaseMul, randScalar } from "../tss/bjj.js";
import { deriveCek, wrapCek, unwrapCek } from "../crypto/kem.js";
import { Kdf } from "../crypto/Kdf.js";
import { toBjjScalar } from "../crypto/index.js";
import { Poseidon } from "../crypto/Poseidon.js";
import { isEvenY, rollToEvenY } from "../note/keys.js";
import { multisigOwner } from "./message.js";

export { NOTE_TYPE_MULTISIG, NOTE_TYPE_STANDARD } from "../note/note.js";

const SELF_EPH_LABEL = "hisoka.msSelfEph";
// Mirrors the standard path's "hisoka.inKey"; ms-prefixed to match the sibling label above, so a group's
// address family is domain-separated from a personal wallet's even if the two secrets ever coincided.
const IN_KEY_LABEL = "hisoka.msInKey";

const MAX_INDEX_ROLL = 256n;

export interface MultisigAddress {
  ownerCommitment: Fr;
  gpk: Point;
  viewPub: Point;
  index: bigint;
}

function assertEvenYViewPub(viewPub: Point): void {
  if (!isEvenY(viewPub)) {
    throw new Error("multisig view key V has a non-canonical odd y");
  }
}

/** Group receiving key for address `index`, from the shared view secret `v`. Every member holds `v`, so any
 *  member can derive any address and scan for it; the group's SPEND authority stays with the FROST quorum. */
export async function deriveMultisigIncomingKey(
  v: Fr,
  index: bigint,
): Promise<Fr> {
  return toBjjScalar(await Kdf.derive(IN_KEY_LABEL, v, new Fr(index)));
}

/** The scanning secret behind a rotated address. Kept separate from `multisigAddress` because that returns
 *  the shareable half; this returns the half a member needs to unwrap the content key. */
export async function multisigIncomingKeyAt(
  v: Fr,
  startIndex: bigint,
): Promise<{ index: bigint; viewKey: Fr; viewPub: Point }> {
  const canonical = await rollToEvenY(
    (i) => deriveMultisigIncomingKey(v, i),
    startIndex,
  );
  return {
    index: canonical.index,
    viewKey: await deriveMultisigIncomingKey(v, canonical.index),
    viewPub: canonical.pub,
  };
}

/** `index` selects which receiving address of the group this is. Rotating it is the only thing that stops a
 *  treasury's whole inbound history sharing one on-chain tag, so it is derived from, not ignored. */
export async function multisigAddress(
  gpk: Point,
  v: Fr,
  index: bigint = 0n,
): Promise<MultisigAddress> {
  const ownerCommitment = new Fr(await multisigOwner(gpk));
  const { index: rolled, viewPub } = await multisigIncomingKeyAt(v, index);
  assertEvenYViewPub(viewPub);
  return { ownerCommitment, gpk, viewPub, index: rolled };
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
