import { describe, it, expect } from "vitest";
import { inCurve } from "@zk-kit/baby-jubjub";
import {
  BASE8,
  IDENTITY,
  scalarMul,
  scalarBaseMul,
  pointEq,
  inSubgroupNonId,
  modSub,
  randScalar,
  polyEval,
  interpolateAtZero,
  SCHNORR_DOMAIN,
} from "../tss/index.js";
import {
  getH,
  pedersenCommit,
  pedersenVerifyShare,
  runGjkrDkg,
} from "../tss/gjkr.js";
import {
  partialDecrypt,
  combine,
  thresholdCek,
  Partial,
} from "../threshold/index.js";

const CONTEXT = SCHNORR_DOMAIN;

async function partialsFor(
  quorum: bigint[],
  shares: Map<bigint, bigint>,
  ephPub: [bigint, bigint],
): Promise<Partial[]> {
  return Promise.all(
    quorum.map((id) => partialDecrypt(id, shares.get(id)!, ephPub)),
  );
}

describe("gjkr: nothing-up-my-sleeve second generator H", () => {
  it("is on-curve, prime-order, and distinct from the identity and Base8", async () => {
    const H = await getH();
    expect(inCurve(H)).toBe(true);
    expect(inSubgroupNonId(H)).toBe(true);
    expect(pointEq(H, IDENTITY)).toBe(false);
    expect(pointEq(H, BASE8)).toBe(false);
  });

  it("is memoized: getH returns the same cached point", async () => {
    expect(pointEq(await getH(), await getH())).toBe(true);
  });
});

describe("gjkr: Pedersen dual-share commitments", () => {
  it("accept a correct dual share and reject either coordinate tampered", async () => {
    const t = 3;
    const aCoeffs = Array.from({ length: t }, () => randScalar());
    const bCoeffs = Array.from({ length: t }, () => randScalar());
    const commitments = await pedersenCommit(aCoeffs, bCoeffs);
    for (let i = 1; i <= 5; i++) {
      const id = BigInt(i);
      const f = polyEval(aCoeffs, id);
      const fPrime = polyEval(bCoeffs, id);
      expect(await pedersenVerifyShare(id, f, fPrime, commitments)).toBe(true);
      expect(
        await pedersenVerifyShare(id, modSub(f + 1n), fPrime, commitments),
      ).toBe(false);
      expect(
        await pedersenVerifyShare(id, f, modSub(fPrime + 1n), commitments),
      ).toBe(false);
    }
  });
});

describe("gjkr: full (3,5) DKG", () => {
  it("produces C == reconstructed_c*Base8 and every share verifies", async () => {
    const { C, shares, V, qual } = await runGjkrDkg(5, 3, CONTEXT);
    expect(qual.length).toBe(5);

    // TEST-ONLY reconstruction; the committee never runs this on c.
    const c = interpolateAtZero(shares, [1n, 2n, 3n]);
    expect(pointEq(scalarBaseMul(c), C)).toBe(true);
    expect(interpolateAtZero(shares, [2n, 4n, 5n])).toBe(c);

    for (const [id, s] of shares) {
      expect(pointEq(V.get(id)!, scalarBaseMul(s))).toBe(true);
    }
  });

  it("disqualifies a dealer that deals a bad Pedersen share, and C stays consistent over the reduced QUAL", async () => {
    const good = await runGjkrDkg(5, 3, CONTEXT);
    expect(good.qual.length).toBe(5);

    const bad = await runGjkrDkg(5, 3, CONTEXT, {
      badShareDealers: new Set([2n]),
    });
    expect(bad.qual).not.toContain(2n);
    expect(bad.qual.length).toBe(4);
    const c = interpolateAtZero(bad.shares, [1n, 3n, 4n]);
    expect(pointEq(scalarBaseMul(c), bad.C)).toBe(true);
  });
});

describe("gjkr: threshold-compliance parity", () => {
  it("combine over GJKR shares reproduces the single-key CEK (c*eph).x across quorums", async () => {
    const { C, shares, V } = await runGjkrDkg(5, 3, CONTEXT);
    const c = interpolateAtZero(shares, [1n, 2n, 3n]);

    const eph = randScalar();
    const ephPub = scalarMul(eph, BASE8);
    const encryptorCek = scalarMul(eph, C)[0]; // (e*C).x == (c*eph).x

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

  it("rejects one valid partial repeated t times (dedup by id before the count gate)", async () => {
    const { shares, V } = await runGjkrDkg(5, 3, CONTEXT);
    const eph = randScalar();
    const ephPub = scalarMul(eph, BASE8);
    const p1 = await partialDecrypt(1n, shares.get(1n)!, ephPub);
    await expect(combine(ephPub, [p1, p1, p1], V, 3)).rejects.toThrow(
      /valid partials/i,
    );
  });
});
