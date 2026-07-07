// Poseidon2 Fiat-Shamir hashing for the (t,n) primitives. Two flavours:
//  - poseidon2 / challengeScalar: a SINGLE Poseidon2 field output. The FROST challenge fed to the circuit is
//    the LOW 248 BITS of that output (`% 2^248`), and the in-circuit verifier and the off-chain signer apply
//    the SAME truncation (frost.nr verify_frost_spend; ciphersuites/bjj.ts challenge). This is a hard
//    soundness invariant: in-circuit `ScalarField<63>` constrains `acc - skew == x` only for scalars
//    < ~2^252, so a canonical (sub-SUBORDER) challenge is required; a full-width challenge hits the
//    unconstrained `ScalarField<64>` path and reopens free-scalar forgery. `challengeScalar` returns the raw
//    field output; the ciphersuite performs the 248-bit truncation so both sides agree byte-for-byte.
//  - hashToScalar: RFC 9380 wide reduction (two squeezes -> ~508 bits -> mod SUBORDER, bias < 2^-128) for
//    OFF-CHAIN-only scalars (rho_i, hedged nonces, Chaum-Pedersen / PoP challenges) that the circuit never
//    recomputes, so uniformity is free.

import { Fr } from "@aztec/foundation/fields";
import { Poseidon } from "../crypto/Poseidon.js";
import { SUBORDER } from "./bjj.js";

/** Poseidon2 over field elements, returning the raw (unreduced) output as a bigint. */
export async function poseidon2(inputs: bigint[]): Promise<bigint> {
  const out = await Poseidon.hash(inputs.map((x) => new Fr(x)));
  return out.toBigInt();
}

/** The raw single Poseidon2 output for the FROST challenge. The caller (the ciphersuite) truncates it to the
 *  low 248 bits, applied IDENTICALLY by the in-circuit verifier -- see this module's header for why the
 *  truncation is soundness-critical. */
export async function challengeScalar(inputs: bigint[]): Promise<bigint> {
  return poseidon2(inputs);
}

// BN254 output width; the high squeeze is shifted by this so the two squeezes never overlap.
const HIGH_SHIFT = 1n << 254n;

/** Uniform hash-to-scalar mod SUBORDER via wide reduction. Domain-separated; for off-chain-only scalars. */
export async function hashToScalar(
  domain: bigint,
  inputs: bigint[],
): Promise<bigint> {
  const high = await poseidon2([domain, ...inputs, 0n]);
  const low = await poseidon2([domain, ...inputs, 1n]);
  return (high * HIGH_SHIFT + low) % SUBORDER;
}
