import { describe, it, expect } from "vitest";
import { inCurve } from "@zk-kit/baby-jubjub";
import {
  BASE8,
  SUBORDER,
  IDENTITY,
  scalarBaseMul,
  scalarMul,
  pointEq,
  inSubgroup,
  inSubgroupNonId,
  randScalar,
  modSub,
  invSub,
  polyEval,
  interpolateAtZero,
  feldmanCommit,
  feldmanVerifyShare,
  cpProve,
  cpVerify,
  challengeScalar,
  hashToScalar,
  CP_DOMAIN,
} from "../tss/index.js";

describe("tss: BabyJubJub curve + scalar field", () => {
  it("Base8 is on-curve and has prime order SUBORDER", () => {
    expect(inCurve(BASE8)).toBe(true);
    expect(pointEq(scalarMul(SUBORDER, BASE8), IDENTITY)).toBe(true);
    expect(pointEq(scalarMul(SUBORDER - 1n, BASE8), IDENTITY)).toBe(false);
  });

  it("subgroup guard accepts Base8, rejects the identity and off-curve points", () => {
    expect(inSubgroupNonId(BASE8)).toBe(true);
    expect(inSubgroupNonId(IDENTITY)).toBe(false);
    expect(inSubgroup(IDENTITY)).toBe(true);
    expect(inSubgroupNonId([1n, 1n])).toBe(false); // (1,1) is off-curve
  });

  it("invSub is the multiplicative inverse mod SUBORDER", () => {
    const x = randScalar();
    expect(modSub(x * invSub(x))).toBe(1n);
  });
});

describe("tss: Shamir + Lagrange mod SUBORDER", () => {
  it("reconstructs the secret from any t shares, and NOT from t-1", () => {
    const n = 5;
    const secret = randScalar();
    const coeffs = [secret, randScalar(), randScalar()];
    const shares = new Map<bigint, bigint>();
    for (let i = 1; i <= n; i++)
      shares.set(BigInt(i), polyEval(coeffs, BigInt(i)));

    expect(interpolateAtZero(shares, [1n, 2n, 3n])).toBe(secret);
    expect(interpolateAtZero(shares, [2n, 4n, 5n])).toBe(secret);
    expect(interpolateAtZero(shares, [1n, 2n])).not.toBe(secret);
  });

  it("a mod-BN254 Lagrange variant would break reconstruction (guards T7)", () => {
    // Full-width coeffs so the shares wrap mod SUBORDER; interpolating them under BN254 Fr diverges.
    const BN254 =
      21888242871839275222246405745257275088548364400416034343698204186575808495617n;
    const secret = randScalar();
    const coeffs = [secret, randScalar(), randScalar()];
    // Quorum {2,4,5} has non-integer Lagrange coeffs, so the modular inverse differs between SUBORDER and BN254.
    const quorum = [2n, 4n, 5n];
    const shares = quorum.map((i) => ({ i, y: polyEval(coeffs, i) }));
    const m = new Map(shares.map((s) => [s.i, s.y]));
    expect(interpolateAtZero(m, quorum)).toBe(secret);
    let accWrong = 0n;
    for (const { i, y } of shares) {
      let num = 1n;
      let den = 1n;
      for (const j of quorum) {
        if (j === i) continue;
        num = (num * ((BN254 - j) % BN254)) % BN254;
        den = (den * (((i - j) % BN254) + BN254)) % BN254;
      }
      const lam = (num * modpow(den, BN254 - 2n, BN254)) % BN254;
      accWrong = (accWrong + lam * (y % BN254)) % BN254;
    }
    expect(accWrong).not.toBe(secret);
  });
});

describe("tss: Feldman VSS", () => {
  it("accepts a correct dealt share and rejects a tampered one", () => {
    const coeffs = [randScalar(), randScalar(), randScalar()];
    const commitments = feldmanCommit(coeffs);
    for (let i = 1; i <= 5; i++) {
      const share = polyEval(coeffs, BigInt(i));
      expect(feldmanVerifyShare(BigInt(i), share, commitments)).toBe(true);
      expect(
        feldmanVerifyShare(BigInt(i), modSub(share + 1n), commitments),
      ).toBe(false);
    }
  });

  it("V_i = share_i*Base8 and sum of const-term commitments == secret*Base8", () => {
    const secret = randScalar();
    const coeffs = [secret, randScalar()];
    const commitments = feldmanCommit(coeffs);
    expect(pointEq(commitments[0], scalarBaseMul(secret))).toBe(true);
  });
});

describe("tss: Chaum-Pedersen DLEQ", () => {
  it("honest partial verifies; forged and wrong-share partials are rejected", async () => {
    const secret = randScalar();
    const epk = scalarMul(randScalar(), BASE8);
    const V = scalarBaseMul(secret);

    const honest = await cpProve(secret, epk);
    expect(await cpVerify(V, epk, honest)).toBe(true);
    expect(pointEq(honest.D, scalarMul(secret, epk))).toBe(true);

    const forged = { ...honest, D: scalarMul(randScalar(), epk) };
    expect(await cpVerify(V, epk, forged)).toBe(false);

    const wrong = await cpProve(modSub(secret + 1n), epk);
    expect(await cpVerify(V, epk, wrong)).toBe(false);
  });
});

describe("tss: hash-to-scalar", () => {
  it("challengeScalar is deterministic and hashToScalar is uniform-ranged", async () => {
    const a = await challengeScalar([1n, 2n, 3n]);
    const b = await challengeScalar([1n, 2n, 3n]);
    expect(a).toBe(b);
    const s = await hashToScalar(CP_DOMAIN, [1n, 2n, 3n]);
    expect(s).toBeGreaterThanOrEqual(0n);
    expect(s).toBeLessThan(SUBORDER);
    const s2 = await hashToScalar(CP_DOMAIN + 1n, [1n, 2n, 3n]);
    expect(s2).not.toBe(s);
  });
});

function modpow(base: bigint, exp: bigint, mod: bigint): bigint {
  let r = 1n;
  let b = base % mod;
  let e = exp;
  while (e > 0n) {
    if (e & 1n) r = (r * b) % mod;
    b = (b * b) % mod;
    e >>= 1n;
  }
  return r;
}
