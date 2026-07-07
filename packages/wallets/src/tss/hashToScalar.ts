// Poseidon2 Fiat-Shamir hashing. The FROST challenge is the LOW 248 BITS of challengeScalar, truncated
// IDENTICALLY off-chain and in-circuit (frost.nr verify_frost_spend); a full-width challenge is unsound.
// hashToScalar is a wide reduction mod SUBORDER for off-chain-only scalars the circuit never recomputes.

import { Fr } from "@aztec/foundation/fields";
import { Poseidon } from "../crypto/Poseidon.js";
import { SUBORDER } from "./bjj.js";

export async function poseidon2(inputs: bigint[]): Promise<bigint> {
  const out = await Poseidon.hash(inputs.map((x) => new Fr(x)));
  return out.toBigInt();
}

export async function challengeScalar(inputs: bigint[]): Promise<bigint> {
  return poseidon2(inputs);
}

const HIGH_SHIFT = 1n << 254n;

export async function hashToScalar(
  domain: bigint,
  inputs: bigint[],
): Promise<bigint> {
  const high = await poseidon2([domain, ...inputs, 0n]);
  const low = await poseidon2([domain, ...inputs, 1n]);
  return (high * HIGH_SHIFT + low) % SUBORDER;
}
