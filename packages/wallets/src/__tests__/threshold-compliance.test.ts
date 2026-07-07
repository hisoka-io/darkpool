import { describe, it, expect } from "vitest";
import {
  BASE8,
  scalarMul,
  scalarBaseMul,
  pointEq,
  IDENTITY,
  randScalar,
  interpolateAtZero,
  SCHNORR_DOMAIN,
} from "../tss/index.js";
import { runDkg } from "../unsafe-sim/index.js";
import {
  partialDecrypt,
  combine,
  thresholdCek,
  thresholdCekRobust,
  Partial,
} from "../threshold/index.js";

const CONTEXT = SCHNORR_DOMAIN; // any fixed context field binds the DKG PoPs

async function partialsFor(
  quorum: bigint[],
  shares: Map<bigint, bigint>,
  ephPub: [bigint, bigint],
): Promise<Partial[]> {
  return Promise.all(
    quorum.map((id) => partialDecrypt(id, shares.get(id)!, ephPub)),
  );
}

describe("threshold-compliance: DKG + threshold decrypt == single-key", () => {
  it("recovers CEK = (c*eph).x uniformly across quorums, matching the single-key holder", async () => {
    const { C, shares, V } = await runDkg(5, 3, CONTEXT);

    // TEST-ONLY reconstruction of c to establish the single-key baseline.
    const c = interpolateAtZero(shares, [1n, 2n, 3n]);
    expect(pointEq(scalarBaseMul(c), C)).toBe(true);

    // A note's ephemeral: eph_pub = e*Base8; the encryptor's CEK for a self note is (e*C).x.
    const e = randScalar();
    const ephPub = scalarMul(e, BASE8);
    const encryptorCek = scalarMul(e, C)[0];

    for (const quorum of [
      [1n, 2n, 3n],
      [2n, 4n, 5n],
      [1n, 4n, 5n],
    ]) {
      const S = await combine(
        ephPub,
        await partialsFor(quorum, shares, ephPub),
        V,
        3,
      );
      // Threshold S == single-key c*eph == e*C, so the same CEK for both note types.
      expect(pointEq(S, scalarMul(c, ephPub))).toBe(true);
      expect(S[0]).toBe(encryptorCek);
      const cek = await thresholdCek(
        ephPub,
        await partialsFor(quorum, shares, ephPub),
        V,
        3,
      );
      expect(cek.toBigInt()).toBe(encryptorCek);
    }
  });

  it("rejects a poisoned partial (Chaum-Pedersen) and stays robust with an honest quorum", async () => {
    const { shares, V } = await runDkg(5, 3, CONTEXT);
    const e = randScalar();
    const ephPub = scalarMul(e, BASE8);

    const all = await partialsFor([1n, 2n, 3n, 4n, 5n], shares, ephPub);
    // Member 3 is malicious: substitute a random point for D_3.
    all[2] = {
      id: 3n,
      proof: { ...all[2].proof, D: scalarMul(randScalar(), ephPub) },
    };

    const { cek, used, excluded } = await thresholdCekRobust(ephPub, all, V, 3);
    expect(excluded).toContain(3n);
    expect(used).not.toContain(3n);
    // The recovered CEK equals the single-key value (reconstruct c off the full sharing for the baseline).
    const c = interpolateAtZero(shares, [1n, 2n, 4n]);
    expect(cek.toBigInt()).toBe(scalarMul(c, ephPub)[0]);
  });

  it("disqualifies a dealer with a bad Feldman share or an invalid PoP", async () => {
    const good = await runDkg(5, 3, CONTEXT);
    expect(good.qual.length).toBe(5);

    const badShare = await runDkg(5, 3, CONTEXT, {
      badShareDealers: new Set([2n]),
    });
    expect(badShare.qual).not.toContain(2n);

    const badPop = await runDkg(5, 3, CONTEXT, {
      badPopDealers: new Set([4n]),
    });
    expect(badPop.qual).not.toContain(4n);
  });

  it("refuses a small-order / identity eph_pub before any c_i*eph_pub", async () => {
    const { shares } = await runDkg(5, 3, CONTEXT);
    await expect(
      partialDecrypt(1n, shares.get(1n)!, IDENTITY),
    ).rejects.toThrow();
    await expect(
      partialDecrypt(1n, shares.get(1n)!, [1n, 1n]),
    ).rejects.toThrow();
  });

  it("rejects one valid partial submitted t times (dedup by id before the count gate)", async () => {
    const { shares, V } = await runDkg(5, 3, CONTEXT);
    const e = randScalar();
    const ephPub = scalarMul(e, BASE8);
    const p1 = await partialDecrypt(1n, shares.get(1n)!, ephPub);

    // Same id thrice -> one distinct partial < threshold 3, so both paths must throw, not silently interpolate.
    await expect(combine(ephPub, [p1, p1, p1], V, 3)).rejects.toThrow(
      /valid partials/i,
    );
    await expect(
      thresholdCekRobust(ephPub, [p1, { ...p1 }, { ...p1 }], V, 3),
    ).rejects.toThrow(/valid partials/i);
  });
});
