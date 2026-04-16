import { randomBytes } from "@aztec/foundation/crypto";
import { leBufferToBigInt } from "@zk-kit/utils/conversions";
import { Point, mulPointEscalar, addPoint, Base8 } from "@zk-kit/baby-jubjub";
import { Poseidon } from "./Poseidon.js";
import { toFr } from "./fields.js";
import { BJJ_SUBGROUP_ORDER } from "./constants.js";

export type DLEQProof = { U: Point<bigint>; V: Point<bigint>; z: bigint };

export async function generateDLEQProof(
  b: bigint,
  C: Point<bigint>,
): Promise<{ B: Point<bigint>; P: Point<bigint>; pi: DLEQProof }> {
  const b_mod = b % BJJ_SUBGROUP_ORDER;
  const r_bigint = leBufferToBigInt(randomBytes(32));
  const r_mod = r_bigint % BJJ_SUBGROUP_ORDER;

  const B = mulPointEscalar(Base8, b_mod);
  const P = mulPointEscalar(C, b_mod);
  const U = mulPointEscalar(Base8, r_mod);
  const V = mulPointEscalar(C, r_mod);

  const hash_inputs = [
    U[0],
    U[1],
    V[0],
    V[1],
    Base8[0],
    Base8[1],
    C[0],
    C[1],
    B[0],
    B[1],
    P[0],
    P[1],
  ].map((val) => toFr(val));
  const e_fr = await Poseidon.hash(hash_inputs);
  const e = e_fr.toBigInt() % BJJ_SUBGROUP_ORDER;

  const eb = (e * b_mod) % BJJ_SUBGROUP_ORDER;
  const z = (r_mod + eb) % BJJ_SUBGROUP_ORDER;

  const zG = mulPointEscalar(Base8, z);
  const eB = mulPointEscalar(B, e);
  const U_plus_eB = addPoint(U, eB);
  const check1_gen = zG[0] === U_plus_eB[0] && zG[1] === U_plus_eB[1];
  if (!check1_gen) {
    throw new Error("DLEQ Proof Generation Check failed: z*G != U + e*B ");
  }

  const pi: DLEQProof = { U, V, z };
  return { B, P, pi };
}

export async function verifyDLEQProof(
  B: Point<bigint>,
  C: Point<bigint>,
  P: Point<bigint>,
  pi: DLEQProof,
): Promise<boolean> {
  const { U, V, z } = pi;

  const hash_inputs = [
    U[0],
    U[1],
    V[0],
    V[1],
    Base8[0],
    Base8[1],
    C[0],
    C[1],
    B[0],
    B[1],
    P[0],
    P[1],
  ].map((val) => toFr(val));
  const e_fr = await Poseidon.hash(hash_inputs);
  const e = e_fr.toBigInt() % BJJ_SUBGROUP_ORDER;

  const zG = mulPointEscalar(Base8, z);
  const eB = mulPointEscalar(B, e);
  const U_plus_eB = addPoint(U, eB);
  if (zG[0] !== U_plus_eB[0] || zG[1] !== U_plus_eB[1]) return false;

  const zC = mulPointEscalar(C, z);
  const eP = mulPointEscalar(P, e);
  const V_plus_eP = addPoint(V, eP);
  if (zC[0] !== V_plus_eP[0] || zC[1] !== V_plus_eP[1]) return false;

  return true;
}
