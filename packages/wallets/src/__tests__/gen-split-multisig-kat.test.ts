import { describe, it, expect } from "vitest";
import { Fr } from "@aztec/foundation/fields";
import { Base8, mulPointEscalar } from "@zk-kit/baby-jubjub";
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
  multisigOwner,
  msgSplit,
  NonceHandle,
  Commitment,
} from "../frost/index.js";
import { leaf, Note } from "../note/note.js";
import { computePsi, computeNullifier } from "../note/nullifier.js";
import { isEvenY } from "../note/keys.js";
import { deriveCek } from "../crypto/kem.js";
import type { Point } from "../tss/index.js";

// Deterministic split_multisig witness + real 3-of-5 FROST (R,z) for split_multisig/src/main.nr.
const ASSET_ID = 0x1234567890123456789012345678901234567890n;
const COMPLIANCE_PK: Point = [
  0x085ed469c9a9f102b6d4f6f909b8ceaf6ca49b39759ac2e0feb7e0aada8b7111n,
  0x245e25ab2bd42f0280a5ade750828dd6868f5225ae798d6b51c676f519c8f4e8n,
];
const OLD_PSI =
  0x0981a88f9e119b057498a4ab99ed5379a1ea91c642454fc0c07aacc1f5cd5731n;
const OLD_VALUE = 100n;
const OUT1_VALUE = 60n;
const OUT2_VALUE = 40n;

function evenYEphsFrom(start: bigint, n: number): bigint[] {
  const out: bigint[] = [];
  let s = start;
  while (out.length < n) {
    if (isEvenY(mulPointEscalar(Base8, s))) out.push(s);
    s++;
  }
  return out;
}

const hex = (x: bigint) => "0x" + x.toString(16).padStart(64, "0");

const msNote = (value: bigint, owner: Fr, psi: Fr, noteType: bigint): Note => ({
  noteVersion: new Fr(1n),
  assetId: new Fr(ASSET_ID),
  noteType: new Fr(noteType),
  conditionsHash: new Fr(0n),
  value,
  owner,
  psi,
  parents: new Fr(0n),
});

describe("gen split_multisig KAT", () => {
  it("emits a coherent witness + real 3-of-5 FROST (R,z) over the split message", async () => {
    const c = 12345678901234567890123456789012345678901234567890n % SUBORDER;
    const coeffs = [
      c,
      98765432109876543210987654321098765432109876543210n % SUBORDER,
      55555555555555555555555555555555555555555555555555n % SUBORDER,
    ];
    const gpk = scalarBaseMul(c);
    const ids = [1n, 2n, 3n];
    const shares = new Map(ids.map((i) => [i, polyEval(coeffs, i)]));
    const owner = new Fr(await multisigOwner(gpk));

    const oldNote = msNote(OLD_VALUE, owner, new Fr(OLD_PSI), 1n);
    const root = await leaf(oldNote);
    const nullifier = await computeNullifier(new Fr(OLD_PSI), new Fr(0n));

    const [eph1, eph2] = evenYEphsFrom(1n, 2);
    const psi1 = await computePsi(deriveCek(new Fr(eph1), COMPLIANCE_PK));
    const psi2 = await computePsi(deriveCek(new Fr(eph2), COMPLIANCE_PK));
    const out1 = msNote(OUT1_VALUE, owner, psi1, 1n);
    const out2 = msNote(OUT2_VALUE, owner, psi2, 1n);
    const out1Leaf = await leaf(out1);
    const out2Leaf = await leaf(out2);

    const m = await msgSplit({
      root: root.toBigInt(),
      nullifier: nullifier.toBigInt(),
      out1Leaf: out1Leaf.toBigInt(),
      out2Leaf: out2Leaf.toBigInt(),
      asset: ASSET_ID,
    });

    const msg = encodeMessage(m);
    const rounds = new Map<
      bigint,
      { nonces: NonceHandle; commitment: Commitment<Point> }
    >();
    for (const i of ids) {
      const h = new Uint8Array(32).fill(Number(i) * 2 + 40);
      const b = new Uint8Array(32).fill(Number(i) * 2 + 41);
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

    expect(hex(gpk[0])).toBe(
      "0x2546ab52faee9ab8ead1ad868567473b9757c6456c137274b12a5c51330d764d",
    );

    // Parity lock: MUST equal the split_multisig/src/main.nr KAT.
    expect(eph1).toBe(4n);
    expect(eph2).toBe(5n);
    expect(hex(psi1.toBigInt())).toBe(
      "0x2aaee0e06ff8b0e8cf78d66b27f27fe9d0e82cc687724cee2eb92b0d8a90c2c2",
    );
    expect(hex(psi2.toBigInt())).toBe(
      "0x0981a88f9e119b057498a4ab99ed5379a1ea91c642454fc0c07aacc1f5cd5731",
    );
    expect(hex(root.toBigInt())).toBe(
      "0x037fe99b619334303b77cbf935d2bb8aa52f392c3c1890d3fe9b093dd8a3f750",
    );
    expect(hex(nullifier.toBigInt())).toBe(
      "0x2761654f0b4e9f47ac9bafe900c723ead042a888da718a34b6ecc8036850755e",
    );
    expect(hex(out1Leaf.toBigInt())).toBe(
      "0x1b2c29f4cffb23c06e49735473d48bd1d8cebb3c21ad0cc6492341168cbc37f1",
    );
    expect(hex(out2Leaf.toBigInt())).toBe(
      "0x0f8bb919f290e3236339c2e946035b49049e55b1e75e35d480e4dd641ffec2c2",
    );
    expect(hex(sig.R[0])).toBe(
      "0x18b6a89104d7879120319bb3cd8c33535d7e654a294b2c42b681992fafdd5293",
    );
    expect(hex(sig.R[1])).toBe(
      "0x0d6be22193de6716d99f345013d474ce018968ac9aa3b836543a3b7515c47e27",
    );
    expect(hex(sig.z)).toBe(
      "0x01a73179db74a78a18abe719d5f5d290530bf8423ebba655d0be46c5af723cec",
    );
    expect(hex(m)).toBe(
      "0x2edf5933bc8d716e7fb741803b4caa653183a9d2df38fd3823da8bf48518e482",
    );
  });
});
