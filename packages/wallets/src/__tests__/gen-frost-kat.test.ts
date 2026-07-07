import { describe, it, expect } from "vitest";
import { scalarBaseMul, polyEval, SUBORDER } from "../tss/index.js";
import {
  bjjCiphersuite as cs,
  encodeMessage,
  commit,
  groupCommitment,
  bindingFactors,
  signShare,
  aggregate,
  verify,
  NonceHandle,
  Commitment,
} from "../frost/index.js";
import type { Point } from "../tss/index.js";

// Emits a DETERMINISTIC 3-of-5 FROST (R,z) over BabyJubJub for the Noir verify_frost_spend KAT: fixed Shamir
// sharing + fixed nonce randomness -> reproducible signature. Run: npx vitest run gen-frost-kat.test.ts
describe("gen frost KAT", () => {
  it("emits a deterministic FROST (R,z)", async () => {
    const c = 12345678901234567890123456789012345678901234567890n % SUBORDER;
    const coeffs = [
      c,
      98765432109876543210987654321098765432109876543210n % SUBORDER,
      55555555555555555555555555555555555555555555555555n % SUBORDER,
    ];
    const gpk = scalarBaseMul(c);
    const ids = [1n, 2n, 3n];
    const shares = new Map(ids.map((i) => [i, polyEval(coeffs, i)]));
    const m =
      0x0abcdef1234567890fedcba9876543210abcdef1234567890fedcba98765432n;
    const msg = encodeMessage(m);

    const rounds = new Map<
      bigint,
      { nonces: NonceHandle; commitment: Commitment<Point> }
    >();
    for (const i of ids) {
      const h = new Uint8Array(32).fill(Number(i) * 2);
      const b = new Uint8Array(32).fill(Number(i) * 2 + 1);
      rounds.set(i, await commit(cs, i, shares.get(i)!, h, b));
    }
    const commitments = ids.map((i) => rounds.get(i)!.commitment);
    const zs: bigint[] = [];
    for (const i of ids)
      zs.push(
        await signShare(
          cs,
          i,
          rounds.get(i)!.nonces,
          shares.get(i)!,
          gpk,
          msg,
          commitments,
        ),
      );
    const R = groupCommitment(
      cs,
      commitments,
      await bindingFactors(cs, gpk, msg, commitments),
    );
    const sig = aggregate(cs, R, zs);
    expect(await verify(cs, gpk, msg, sig)).toBe(true);

    // Parity lock: the TS signer must regenerate the exact values hard-coded in the Noir verify_frost_spend
    // KAT (shared/src/frost.nr). A drift in the TS FROST hashing breaks BOTH this assertion and the Noir KAT.
    const hex = (x: bigint) => "0x" + x.toString(16).padStart(64, "0");
    expect(hex(gpk[0])).toBe(
      "0x2546ab52faee9ab8ead1ad868567473b9757c6456c137274b12a5c51330d764d",
    );
    expect(hex(gpk[1])).toBe(
      "0x0d7a564269d3675f75799ee9d7574b00d01190b243041994c0e460af507a71aa",
    );
    expect(hex(sig.R[0])).toBe(
      "0x262d28e21d283e57d8add3efde5b0ef36d18af221efa12d686b50fdae23c0b53",
    );
    expect(hex(sig.R[1])).toBe(
      "0x20dba1d0aa62eab7f32a1a9eb2f4cb382080c3ea369f7422f9e27c075b9db09d",
    );
    expect(hex(sig.z)).toBe(
      "0x02e3508cb36163fef3481853d79756edf5c2c7565de8094cd5fca125c58dcfe2",
    );
    expect(hex(m)).toBe(
      "0x00abcdef1234567890fedcba9876543210abcdef1234567890fedcba98765432",
    );
  });
});
