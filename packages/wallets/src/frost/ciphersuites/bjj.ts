// Production FROST ciphersuite: BabyJubJub + Poseidon2. The challenge is byte-identical to the in-circuit e.

import { Ciphersuite, Commitment } from "../ciphersuite.js";
import {
  Point,
  BASE8,
  IDENTITY,
  SUBORDER,
  pointAdd,
  pointNeg,
  pointEq,
  scalarMul,
} from "../../tss/bjj.js";
import {
  challengeScalar,
  hashToScalar,
  poseidon2,
} from "../../tss/hashToScalar.js";
import {
  SCHNORR_DOMAIN,
  FROST_RHO_DOMAIN,
  FROST_NONCE_DOMAIN,
  FROST_MSG_DOMAIN,
  FROST_COM_DOMAIN,
} from "../../tss/domains.js";

const BN254_P =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

export function encodeMessage(m: bigint): Uint8Array {
  const out = new Uint8Array(32);
  let v = m;
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

function decodeMessage(msg: Uint8Array): bigint {
  let v = 0n;
  for (const b of msg) v = (v << 8n) | BigInt(b);
  return v % BN254_P;
}

function bytesToField(bytes: Uint8Array): bigint {
  let v = 0n;
  for (const b of bytes) v = (v << 8n) | BigInt(b);
  return v % BN254_P;
}

async function hashMessage(msg: Uint8Array): Promise<bigint> {
  return poseidon2([FROST_MSG_DOMAIN, decodeMessage(msg)]);
}

async function hashCommitmentList(
  commitments: Commitment<Point>[],
): Promise<bigint> {
  const sorted = [...commitments].sort((a, b) =>
    a.id < b.id ? -1 : a.id > b.id ? 1 : 0,
  );
  const fields: bigint[] = [FROST_COM_DOMAIN];
  for (const c of sorted) {
    fields.push(c.id, c.D[0], c.D[1], c.E[0], c.E[1]);
  }
  return poseidon2(fields);
}

export const bjjCiphersuite: Ciphersuite<Point> = {
  name: "FROST-BABYJUBJUB-POSEIDON2-v1",
  generator: BASE8,
  identity: IDENTITY,
  add: pointAdd,
  scalarMul,
  negate: pointNeg,
  eq: pointEq,
  order: SUBORDER,

  async nonceScalar(random32: Uint8Array, secret: bigint): Promise<bigint> {
    return hashToScalar(FROST_NONCE_DOMAIN, [bytesToField(random32), secret]);
  },

  async bindingFactor(
    gpk: Point,
    msg: Uint8Array,
    commitments: Commitment<Point>[],
    id: bigint,
  ): Promise<bigint> {
    const h4 = await hashMessage(msg);
    const h5 = await hashCommitmentList(commitments);
    return hashToScalar(FROST_RHO_DOMAIN, [gpk[0], gpk[1], h4, h5, id]);
  },

  async challenge(R: Point, gpk: Point, msg: Uint8Array): Promise<bigint> {
    // Low 248 bits, applied identically in-circuit (verify_frost_spend); a full-width challenge is unsound.
    const full = await challengeScalar([
      SCHNORR_DOMAIN,
      R[0],
      R[1],
      gpk[0],
      gpk[1],
      decodeMessage(msg),
    ]);
    return full % (1n << 248n);
  },
};
