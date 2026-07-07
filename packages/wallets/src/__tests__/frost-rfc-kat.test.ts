// Certifies the generic FROST protocol (frost.ts) against the official RFC 9591 known-answer vectors, via the
// FROST(ristretto255, SHA-512) ciphersuite (RFC 9591 Section 6.2). If every stage matches the recorded KAT,
// the protocol LOGIC that production runs over BabyJubJub+Poseidon2 is correct. The single official vector is
// VENDORED as a tracked fixture (provenance: RFC 9591 Section 6.2) and read relative to this file, so the
// certification runs in CI / a clean clone, not just on one dev's machine.

import { describe, it, expect, beforeAll } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { ed25519, RistrettoPoint } from "@noble/curves/ed25519";
import {
  bytesToHex,
  hexToBytes,
  bytesToNumberLE,
  numberToBytesLE,
  concatBytes,
} from "@noble/curves/abstract/utils";
import {
  ristretto255Ciphersuite as cs,
  bindingFactorInput,
} from "../frost/ciphersuites/ristretto255.js";
import {
  bindingFactors,
  groupCommitment,
  signShareUnchecked,
  aggregate,
  verify,
  verifySignatureShare,
} from "../frost/frost.js";
import type { Nonces, Signature } from "../frost/frost.js";
import type { Commitment } from "../frost/ciphersuite.js";

type Point = InstanceType<typeof RistrettoPoint>;

const KAT_PATH = fileURLToPath(
  new URL("./vectors/frost-ristretto255-sha512.json", import.meta.url),
);

function loadKat(): Kat {
  try {
    return JSON.parse(readFileSync(KAT_PATH, "utf8")) as Kat;
  } catch (err) {
    const why = err instanceof Error ? err.message : String(err);
    throw new Error(
      `RFC 9591 FROST(ristretto255,SHA-512) KAT fixture missing or unreadable at ${KAT_PATH} ` +
        `(${why}). It must be a tracked file under src/__tests__/vectors/.`,
    );
  }
}

interface RoundOne {
  identifier: number;
  hiding_nonce_randomness: string;
  binding_nonce_randomness: string;
  hiding_nonce: string;
  binding_nonce: string;
  hiding_nonce_commitment: string;
  binding_nonce_commitment: string;
  binding_factor_input: string;
  binding_factor: string;
}
interface RoundTwo {
  identifier: number;
  sig_share: string;
}
interface Kat {
  inputs: {
    participant_list: number[];
    group_public_key: string;
    message: string;
    participant_shares: { identifier: number; participant_share: string }[];
  };
  round_one_outputs: { outputs: RoundOne[] };
  round_two_outputs: { outputs: RoundTwo[] };
  final_output: { sig: string };
}

const L = cs.order;
const scalarHex = (s: bigint): string =>
  bytesToHex(numberToBytesLE(((s % L) + L) % L, 32));
const elemHex = (p: Point): string => bytesToHex(p.toRawBytes());

interface SignerState {
  id: bigint;
  secret: bigint;
  nonces: Nonces;
  commitment: Commitment<Point>;
  publicShare: Point;
  round1: RoundOne;
  round2: RoundTwo;
}
interface Transcript {
  kat: Kat;
  gpk: Point;
  msg: Uint8Array;
  signers: SignerState[];
  commitments: Commitment<Point>[];
  rhos: Map<bigint, bigint>;
  R: Point;
  challenge: bigint;
  sig: Signature<Point>;
}

let tx: Transcript;

beforeAll(async () => {
  const kat = loadKat();
  const gpk = RistrettoPoint.fromHex(kat.inputs.group_public_key);
  const msg = hexToBytes(kat.inputs.message);

  const secretOf = (id: number): bigint => {
    const rec = kat.inputs.participant_shares.find((s) => s.identifier === id);
    if (rec === undefined) throw new Error(`kat: no share for ${id}`);
    return bytesToNumberLE(hexToBytes(rec.participant_share)) % L;
  };
  const round2Of = (id: number): RoundTwo => {
    const rec = kat.round_two_outputs.outputs.find((o) => o.identifier === id);
    if (rec === undefined)
      throw new Error(`kat: no round-two output for ${id}`);
    return rec;
  };

  const signers: SignerState[] = [];
  for (const round1 of kat.round_one_outputs.outputs) {
    const secret = secretOf(round1.identifier);
    // Reconstruct the one-time nonces from the KAT-recorded randomness (production draws fresh CSPRNG bytes).
    const d = await cs.nonceScalar(
      hexToBytes(round1.hiding_nonce_randomness),
      secret,
    );
    const e = await cs.nonceScalar(
      hexToBytes(round1.binding_nonce_randomness),
      secret,
    );
    const D = cs.scalarMul(d, cs.generator);
    const E = cs.scalarMul(e, cs.generator);
    const id = BigInt(round1.identifier);
    signers.push({
      id,
      secret,
      nonces: { d, e },
      commitment: { id, D, E },
      publicShare: cs.scalarMul(secret, cs.generator),
      round1,
      round2: round2Of(round1.identifier),
    });
  }

  const commitments = signers.map((s) => s.commitment);
  const rhos = await bindingFactors(cs, gpk, msg, commitments);
  const R = groupCommitment(cs, commitments, rhos);
  const challenge = await cs.challenge(R, gpk, msg);

  const zShares: bigint[] = [];
  for (const s of signers) {
    zShares.push(
      await signShareUnchecked(
        cs,
        s.id,
        s.nonces,
        s.secret,
        gpk,
        msg,
        commitments,
      ),
    );
  }
  const sig = aggregate(cs, R, zShares);

  tx = { kat, gpk, msg, signers, commitments, rhos, R, challenge, sig };
});

describe("FROST(ristretto255, SHA-512) against RFC 9591 KAT", () => {
  it("reconstructs each signer's nonces and commitments from the recorded randomness", () => {
    for (const s of tx.signers) {
      expect(scalarHex(s.nonces.d)).toBe(s.round1.hiding_nonce);
      expect(scalarHex(s.nonces.e)).toBe(s.round1.binding_nonce);
      expect(elemHex(s.commitment.D)).toBe(s.round1.hiding_nonce_commitment);
      expect(elemHex(s.commitment.E)).toBe(s.round1.binding_nonce_commitment);
    }
  });

  it("(a) binding_factor_input matches the recorded rho preimage", () => {
    for (const s of tx.signers) {
      const input = bindingFactorInput(tx.gpk, tx.msg, tx.commitments, s.id);
      expect(bytesToHex(input)).toBe(s.round1.binding_factor_input);
    }
  });

  it("(b) binding_factor matches cs.bindingFactor", async () => {
    for (const s of tx.signers) {
      expect(scalarHex(tx.rhos.get(s.id)!)).toBe(s.round1.binding_factor);
      const direct = await cs.bindingFactor(
        tx.gpk,
        tx.msg,
        tx.commitments,
        s.id,
      );
      expect(scalarHex(direct)).toBe(s.round1.binding_factor);
    }
  });

  it("(c) group commitment R matches the R half of the final signature", () => {
    expect(elemHex(tx.R)).toBe(tx.kat.final_output.sig.slice(0, 64));
  });

  it("(d) challenge matches an independent RFC 6.2 recomputation", () => {
    const ctx = new TextEncoder().encode("FROST-RISTRETTO255-SHA512-v1");
    const label = new TextEncoder().encode("chal");
    const digest = ed25519.CURVE.hash(
      concatBytes(ctx, label, tx.R.toRawBytes(), tx.gpk.toRawBytes(), tx.msg),
    );
    const expected = bytesToNumberLE(digest) % L;
    expect(tx.challenge).toBe(expected);
  });

  it("(e) each sig_share equals signShare(cs, ...)", async () => {
    for (const s of tx.signers) {
      const z = await signShareUnchecked(
        cs,
        s.id,
        s.nonces,
        s.secret,
        tx.gpk,
        tx.msg,
        tx.commitments,
      );
      expect(scalarHex(z)).toBe(s.round2.sig_share);
    }
  });

  it("(f) aggregate equals the final RFC signature", () => {
    expect(elemHex(tx.sig.R) + scalarHex(tx.sig.z)).toBe(
      tx.kat.final_output.sig,
    );
  });

  it("(g) verify() accepts the aggregated signature", async () => {
    expect(await verify(cs, tx.gpk, tx.msg, tx.sig)).toBe(true);
  });

  it("(g) verifySignatureShare() accepts every signer's partial", async () => {
    for (const s of tx.signers) {
      const z = await signShareUnchecked(
        cs,
        s.id,
        s.nonces,
        s.secret,
        tx.gpk,
        tx.msg,
        tx.commitments,
      );
      const ok = await verifySignatureShare(
        cs,
        s.id,
        z,
        s.publicShare,
        tx.gpk,
        tx.msg,
        tx.commitments,
      );
      expect(ok).toBe(true);
    }
  });
});
