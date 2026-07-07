import { describe, it, expect } from "vitest";
import { SCHNORR_DOMAIN, scalarMul, BASE8, pointEq } from "../tss/index.js";
import { runDkg } from "../unsafe-sim/index.js";
import { challengeScalar } from "../tss/hashToScalar.js";
import {
  bjjCiphersuite as cs,
  encodeMessage,
  commit,
  groupCommitment,
  bindingFactors,
  signShare,
  signShareUnchecked,
  coordinatorAggregate,
  verifySignatureShare,
  aggregate,
  verify,
  Commitment,
  NonceHandle,
} from "../frost/index.js";
import type { Point } from "../tss/index.js";

const CONTEXT = SCHNORR_DOMAIN;

function rand32(): Uint8Array {
  const b = new Uint8Array(32);
  globalThis.crypto.getRandomValues(b);
  return b;
}

async function frostSign(
  quorum: bigint[],
  shares: Map<bigint, bigint>,
  gpk: Point,
  m: bigint,
) {
  const msg = encodeMessage(m);
  const rounds = new Map<
    bigint,
    { nonces: NonceHandle; commitment: Commitment<Point> }
  >();
  for (const id of quorum) {
    rounds.set(id, await commit(cs, id, shares.get(id)!, rand32(), rand32()));
  }
  const commitments = quorum.map((id) => rounds.get(id)!.commitment);
  const zShares: bigint[] = [];
  for (const id of quorum) {
    const z = await signShare(
      cs,
      id,
      rounds.get(id)!.nonces,
      shares.get(id)!,
      gpk,
      msg,
      commitments,
    );
    const ok = await verifySignatureShare(
      cs,
      id,
      z,
      scalarMul(shares.get(id)!, BASE8),
      gpk,
      msg,
      commitments,
    );
    expect(ok).toBe(true);
    zShares.push(z);
  }
  const rhos = await bindingFactors(cs, gpk, msg, commitments);
  const R = groupCommitment(cs, commitments, rhos);
  return aggregate(cs, R, zShares);
}

describe("FROST over BabyJubJub+Poseidon2: 2-round sign", () => {
  it("a t-of-n quorum produces an (R,z) that verifies under gpk (== single-key Schnorr)", async () => {
    const { C: gpk, shares } = await runDkg(5, 3, CONTEXT);
    const m = 0x1234567890abcdefn;
    const sig = await frostSign([1n, 2n, 3n], shares, gpk, m);
    expect(await verify(cs, gpk, encodeMessage(m), sig)).toBe(true);

    // The sig's challenge is what the circuit recomputes: low 248 bits of Poseidon2, matching verify_frost_spend.
    const eCircuit =
      (await challengeScalar([
        SCHNORR_DOMAIN,
        sig.R[0],
        sig.R[1],
        gpk[0],
        gpk[1],
        m,
      ])) %
      (1n << 248n);
    const lhs = scalarMul(sig.z, BASE8);
    const rhs = cs.add(sig.R, scalarMul(eCircuit, gpk));
    expect(pointEq(lhs, rhs)).toBe(true);
  });

  it("different quorums produce different but equally-valid signatures under the same gpk", async () => {
    const { C: gpk, shares } = await runDkg(5, 3, CONTEXT);
    const m = 0xdeadbeefn;
    const sigA = await frostSign([1n, 2n, 3n], shares, gpk, m);
    const sigB = await frostSign([2n, 4n, 5n], shares, gpk, m);
    expect(await verify(cs, gpk, encodeMessage(m), sigA)).toBe(true);
    expect(await verify(cs, gpk, encodeMessage(m), sigB)).toBe(true);
  });

  it("message-binding: a signature for m1 does NOT verify for m2", async () => {
    const { C: gpk, shares } = await runDkg(5, 3, CONTEXT);
    const sig = await frostSign([1n, 2n, 3n], shares, gpk, 111n);
    expect(await verify(cs, gpk, encodeMessage(111n), sig)).toBe(true);
    expect(await verify(cs, gpk, encodeMessage(222n), sig)).toBe(false);
  });

  it("a sub-threshold (t-1) quorum cannot produce a verifying signature", async () => {
    const { C: gpk, shares } = await runDkg(5, 3, CONTEXT);
    const m = 999n;
    const sig = await frostSign([1n, 2n], shares, gpk, m);
    expect(await verify(cs, gpk, encodeMessage(m), sig)).toBe(false);
  });

  it("a group commitment assembled WITHOUT the per-participant binding factor rho_i is rejected", async () => {
    const { C: gpk, shares } = await runDkg(5, 3, CONTEXT);
    const quorum = [1n, 2n, 3n];
    const msg = encodeMessage(0x5a5an);
    const rounds = new Map<
      bigint,
      { nonces: NonceHandle; commitment: Commitment<Point> }
    >();
    for (const id of quorum)
      rounds.set(id, await commit(cs, id, shares.get(id)!, rand32(), rand32()));
    const commitments = quorum.map((id) => rounds.get(id)!.commitment);

    const zShares: bigint[] = [];
    for (const id of quorum)
      zShares.push(
        await signShare(
          cs,
          id,
          rounds.get(id)!.nonces,
          shares.get(id)!,
          gpk,
          msg,
          commitments,
        ),
      );
    const rhos = await bindingFactors(cs, gpk, msg, commitments);
    const { z } = aggregate(
      cs,
      groupCommitment(cs, commitments, rhos),
      zShares,
    );
    expect(
      await verify(cs, gpk, msg, {
        R: groupCommitment(cs, commitments, rhos),
        z,
      }),
    ).toBe(true);

    // Reassemble R with rho_i = 1 (no per-participant binding): the honestly-bound partials no longer match,
    // so verify rejects. The rho_i binding (RFC 9591 4.4) is what blocks ROS/Wagner parallel-session forgery.
    const unitRhos = new Map<bigint, bigint>(quorum.map((id) => [id, 1n]));
    const unboundR = groupCommitment(cs, commitments, unitRhos);
    expect(await verify(cs, gpk, msg, { R: unboundR, z })).toBe(false);
  });

  it("a commit() nonce handle is consume-once: a second signShare with it THROWS", async () => {
    const { C: gpk, shares } = await runDkg(5, 3, CONTEXT);
    const quorum = [1n, 2n, 3n];
    const msg = encodeMessage(0x77n);
    const rounds = new Map<
      bigint,
      { nonces: NonceHandle; commitment: Commitment<Point> }
    >();
    for (const id of quorum)
      rounds.set(id, await commit(cs, id, shares.get(id)!, rand32(), rand32()));
    const commitments = quorum.map((id) => rounds.get(id)!.commitment);

    const handle = rounds.get(1n)!.nonces;
    await signShare(cs, 1n, handle, shares.get(1n)!, gpk, msg, commitments);
    await expect(
      signShare(cs, 1n, handle, shares.get(1n)!, gpk, msg, commitments),
    ).rejects.toThrow(/consumed|reuse/i);
  });

  it("signShareUnchecked (KAT path) accepts a bare reusable nonce; the handle path stays single-use", async () => {
    const { C: gpk, shares } = await runDkg(5, 3, CONTEXT);
    const quorum = [1n, 2n, 3n];
    const msg = encodeMessage(0x99n);
    const rounds = new Map<
      bigint,
      { nonces: NonceHandle; commitment: Commitment<Point> }
    >();
    for (const id of quorum)
      rounds.set(id, await commit(cs, id, shares.get(id)!, rand32(), rand32()));
    const commitments = quorum.map((id) => rounds.get(id)!.commitment);

    const bare = { d: rounds.get(1n)!.nonces.d, e: rounds.get(1n)!.nonces.e };
    const z1 = await signShareUnchecked(
      cs,
      1n,
      bare,
      shares.get(1n)!,
      gpk,
      msg,
      commitments,
    );
    const z2 = await signShareUnchecked(
      cs,
      1n,
      bare,
      shares.get(1n)!,
      gpk,
      msg,
      commitments,
    );
    expect(z1).toBe(z2);
  });
});

describe("FROST coordinator aggregation: dedup + threshold gate", () => {
  interface Partial {
    id: bigint;
    z: bigint;
    publicShare: Point;
  }
  async function buildPartials(
    quorum: bigint[],
    shares: Map<bigint, bigint>,
    gpk: Point,
    m: bigint,
  ): Promise<{
    commitments: Commitment<Point>[];
    partials: Partial[];
    R: Point;
    msg: Uint8Array;
  }> {
    const msg = encodeMessage(m);
    const rounds = new Map<
      bigint,
      { nonces: NonceHandle; commitment: Commitment<Point> }
    >();
    for (const id of quorum)
      rounds.set(id, await commit(cs, id, shares.get(id)!, rand32(), rand32()));
    const commitments = quorum.map((id) => rounds.get(id)!.commitment);
    const partials: Partial[] = [];
    for (const id of quorum) {
      const z = await signShare(
        cs,
        id,
        rounds.get(id)!.nonces,
        shares.get(id)!,
        gpk,
        msg,
        commitments,
      );
      partials.push({ id, z, publicShare: scalarMul(shares.get(id)!, BASE8) });
    }
    const rhos = await bindingFactors(cs, gpk, msg, commitments);
    const R = groupCommitment(cs, commitments, rhos);
    return { commitments, partials, R, msg };
  }

  it("verifies then aggregates a full quorum of distinct shares", async () => {
    const { C: gpk, shares } = await runDkg(5, 3, CONTEXT);
    const { commitments, partials, R, msg } = await buildPartials(
      [1n, 2n, 3n],
      shares,
      gpk,
      42n,
    );
    const sig = await coordinatorAggregate(
      cs,
      R,
      gpk,
      msg,
      commitments,
      partials,
      3,
    );
    expect(await verify(cs, gpk, msg, sig)).toBe(true);
  });

  it("rejects a duplicated share (replay) before aggregating", async () => {
    const { C: gpk, shares } = await runDkg(5, 3, CONTEXT);
    const { commitments, partials, R, msg } = await buildPartials(
      [1n, 2n, 3n],
      shares,
      gpk,
      43n,
    );
    await expect(
      coordinatorAggregate(
        cs,
        R,
        gpk,
        msg,
        commitments,
        [...partials, partials[0]],
        3,
      ),
    ).rejects.toThrow(/duplicate/i);
  });

  it("rejects a sub-threshold set of distinct shares", async () => {
    const { C: gpk, shares } = await runDkg(5, 3, CONTEXT);
    const { commitments, partials, R, msg } = await buildPartials(
      [1n, 2n, 3n],
      shares,
      gpk,
      44n,
    );
    await expect(
      coordinatorAggregate(
        cs,
        R,
        gpk,
        msg,
        commitments,
        partials.slice(0, 2),
        3,
      ),
    ).rejects.toThrow(/threshold/i);
  });
});
