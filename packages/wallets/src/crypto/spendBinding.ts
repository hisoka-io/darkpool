import { Point, mulPointEscalar, addPoint, Base8 } from "@zk-kit/baby-jubjub";
import { Poseidon } from "./Poseidon.js";
import { toFr } from "./fields.js";
import { BJJ_SUBGROUP_ORDER } from "./constants.js";

export type SpendBinding = { R: Point<bigint>; s: bigint };

async function challenge(
  R: Point<bigint>,
  B: Point<bigint>,
  S: Point<bigint>,
): Promise<bigint> {
  const e_fr = await Poseidon.hash(
    [R[0], R[1], B[0], B[1], S[0], S[1]].map((v) => toFr(v)),
  );
  return e_fr.toBigInt() % BJJ_SUBGROUP_ORDER;
}

export async function signSpendBinding(
  ivk: bigint,
  pkSpend: Point<bigint>,
  nonce: bigint,
): Promise<SpendBinding> {
  const ivk_mod = ivk % BJJ_SUBGROUP_ORDER;
  const r = nonce % BJJ_SUBGROUP_ORDER;
  if (r === 0n) throw new Error("Spend-binding nonce reduces to zero");

  const B = mulPointEscalar(Base8, ivk_mod);
  const R = mulPointEscalar(Base8, r);
  const e = await challenge(R, B, pkSpend);
  const s = (r + ((e * ivk_mod) % BJJ_SUBGROUP_ORDER)) % BJJ_SUBGROUP_ORDER;
  return { R, s };
}

export async function verifySpendBinding(
  B: Point<bigint>,
  pkSpend: Point<bigint>,
  binding: SpendBinding,
): Promise<boolean> {
  const { R, s } = binding;
  const e = await challenge(R, B, pkSpend);
  const sB = mulPointEscalar(Base8, s);
  const eB = mulPointEscalar(B, e);
  const R_plus_eB = addPoint(R, eB);
  return sB[0] === R_plus_eB[0] && sB[1] === R_plus_eB[1];
}
