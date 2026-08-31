// owner=Poseidon2(gpk) is DECOUPLED from the view key V=v*Base8. Discovery tags are point.x, so V and every eph_pub must be even-y.

import { Fr } from "@aztec/foundation/fields";
import { Point, scalarBaseMul } from "../tss/bjj.js";
import type { EphemeralCounterStore } from "../state/EphemeralCounterStore.js";
import {
  type DerivedEph,
  asDerivedEph,
  markDerivedSelfMintCandidate,
} from "../types/ephemeral.js";
import { deriveCek, wrapCek, unwrapCek } from "../crypto/kem.js";
import { Kdf } from "../crypto/Kdf.js";
import { toBjjScalar } from "../crypto/index.js";
import { Poseidon } from "../crypto/Poseidon.js";
import { isEvenY, rollToEvenY } from "../note/keys.js";
import { multisigOwner } from "./message.js";
import type { SelfMintAuthorization } from "../discovery/preflight.js";
import { consumeSelfMints } from "../discovery/preflight.js";
import type { CompleteComplianceHistory } from "../note/complianceKeys.js";
import type { SelfMintDomain } from "../discovery/types.js";

export { NOTE_TYPE_MULTISIG, NOTE_TYPE_STANDARD } from "../note/note.js";

const SELF_EPH_LABEL = "hisoka.msSelfEph";
// Mirrors the standard path's "hisoka.inKey"; ms-prefixed to match the sibling label above, so a group's
// address family is domain-separated from a personal wallet's even if the two secrets ever coincided.
const IN_KEY_LABEL = "hisoka.msInKey";

const MAX_INDEX_ROLL = 256n;

/**
 * The counter scope for a member's self-family indices.
 *
 * Keyed on a commitment to the VIEW SECRET, not on the owner commitment, because the ephemeral family
 * is a pure function of (v, memberId, j). Keying it on the group's signing key would reset the counter
 * whenever gpk rotates while v survives, reissuing indices against an unchanged family and two-time-
 * padding the DEM. A commitment rather than v itself, because a scope string reaches a durable store.
 */
async function depositScope(v: Fr, memberId: bigint): Promise<string> {
  return `msSelf:${(await Poseidon.hash([v])).toString()}:${memberId}`;
}

declare const selfMintBrand: unique symbol;

/**
 * The witness a self-family mint must carry: the derived scalar plus the index it came from.
 *
 * Branded as well as typed, so it cannot be assembled structurally. `canonicalMultisigSelfTag` is on the
 * public barrel and derives from a caller-chosen index with no counter, so without this brand a caller
 * could widen its result into a mint witness and reach the two-time-pad the counter exists to prevent.
 * `multisigDepositEph` is the only producer, and it is the only path that reserves an index.
 */
export interface MultisigSelfMint {
  readonly eph: DerivedEph;
  readonly ephPub: Point;
  readonly tag: Fr;
  readonly j: bigint;
  readonly memberId: bigint;
  readonly index: number;
  readonly [selfMintBrand]: true;
}

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
): Promise<{ eph: DerivedEph; ephPub: Point }> {
  const salt = await memberSalt(memberId, j);
  const eph = toBjjScalar(await Kdf.derive(SELF_EPH_LABEL, v, salt));
  return { eph: asDerivedEph(eph), ephPub: scalarBaseMul(eph.toBigInt()) };
}

export interface CanonicalMultisigSelfTag {
  eph: DerivedEph;
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

/**
 * Builds the self-family note key material from a mint witness.
 *
 * It takes the witness rather than a bare scalar because the tag it emits is the ephemeral's own public
 * x: a scalar that was sampled instead of derived yields a tag no scanner registers, and the note is
 * then invisible and unspendable with no error raised anywhere.
 */
export async function buildSelfNote(
  authorization: SelfMintAuthorization,
  compliancePk: Point,
  complianceVersion: number,
  complianceHistory: CompleteComplianceHistory,
  domain: SelfMintDomain,
  gpk: Point,
): Promise<SelfMultisigNote> {
  const ownerCommitment = new Fr(await multisigOwner(gpk));
  const [mint] = consumeSelfMints([authorization], {
    ownerCommitment,
    compliancePk,
    complianceVersion,
    complianceHistory,
    chainId: domain.chainId,
    poolAddress: domain.poolAddress,
    deploymentAnchor: domain.deploymentAnchor,
  });
  // Recomputed rather than trusted. The witness carries three fields that must agree, and taking them
  // on faith would let a caller assemble a note whose advertised tag is not the tag its scalar produces,
  // which is the same undiscoverable outcome by a different route.
  const ephPub = scalarBaseMul(mint.eph.toBigInt());
  if (ephPub[0] !== mint.ephPub[0] || ephPub[1] !== mint.ephPub[1]) {
    throw new Error(
      "multisig self mint witness is inconsistent: eph_pub does not match the ephemeral scalar",
    );
  }
  if (!mint.tag.equals(new Fr(ephPub[0]))) {
    throw new Error(
      "multisig self mint witness is inconsistent: tag is not eph_pub.x",
    );
  }
  return { cek: deriveCek(mint.eph, compliancePk), tag: mint.tag, ephPub };
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

/**
 * Reserves a durable index and derives the self-family ephemeral for a group deposit or change output.
 *
 * The index comes from the counter store rather than from randomness, and it is reserved before it is
 * handed out: a crash skips indices but can never reissue one, because a reissued index reuses the CEK
 * and two-time-pads the DEM keystream, which publicly links both notes to one wallet.
 *
 * It reuses the scanner's self-tag family. `gpk` is trusted local integration input and binds the
 * candidate to the declared group owner; this function does not prove that `v` belongs to `gpk`.
 */
export async function multisigDepositEph(
  v: Fr,
  memberId: bigint,
  counters: EphemeralCounterStore,
  gpk: Point,
): Promise<MultisigSelfMint> {
  const scope = await depositScope(v, memberId);
  for (let attempt = 0n; attempt < MAX_INDEX_ROLL; attempt++) {
    const reservation = await counters.reserve(scope, 1);
    const j = BigInt(reservation.base);
    const { eph, ephPub } = await deriveSelfEph(v, memberId, j);
    if (!isEvenY(ephPub)) {
      // The reservation stays burned so this deterministic derivation cannot revisit an odd-y index.
      continue;
    }
    await reservation.commit(reservation.base);
    return markDerivedSelfMintCandidate(
      {
        eph,
        ephPub,
        tag: new Fr(ephPub[0]),
        j,
        memberId,
        index: reservation.base,
      } as MultisigSelfMint,
      new Fr(await multisigOwner(gpk)),
    );
  }
  throw new Error(
    `multisig: no even-y self ephemeral within ${MAX_INDEX_ROLL} reservations for member ${memberId}`,
  );
}
