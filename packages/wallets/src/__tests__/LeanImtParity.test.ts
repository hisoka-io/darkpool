import { describe, it, expect } from "vitest";
import { LeanIMT } from "../merkle/LeanIMT.js";
import { toFr } from "../crypto/fields.js";

// Noir<->TS LeanIMT parity at deep indices. The circuit's lean_imt_inclusion_proof
// (packages/circuits/shared/src/lib.nr, kat_leanimt_tri_parity) asserts these exact roots; this test proves the
// TS LeanIMT reference reproduces them, so a drift in the "right-zero-sibling -> parent = left child" lean
// semantics on either side fails CI. A historical mismatch of this kind silently failed all proofs (CLAUDE.md).
// Depth 32 (frozen); leaves are 1..n, matching sandbox/gen_leanimt_parity.ts.
const DEPTH = 32;

async function treeOf(n: number): Promise<LeanIMT> {
  const t = new LeanIMT(DEPTH);
  for (let i = 1; i <= n; i++) await t.insert(toFr(BigInt(i)));
  return t;
}

const CASES: Array<{ n: number; root: string }> = [
  {
    n: 16,
    root: "0x1528946361c480e8dc1e9ae3f8c31c997625fa1ddeddc7db5ad0dce3ac58fc4c",
  },
  {
    n: 17,
    root: "0x2c49c87b6901221e46e91d5cd747a5f6b4c153585cb43e5ea8f28b24a2e1503a",
  },
  {
    n: 33,
    root: "0x048b0596ca42fe3afab1983a0016c40b2b49eabed0774536b7545b47a5a45ced",
  },
  {
    n: 40,
    root: "0x2b883a20a8fd7d17d73dc541e897b09a885cbbdd18cdfe481588a31e727de8b3",
  },
];

describe("LeanIMT Noir<->TS parity (deep indices)", () => {
  for (const { n, root } of CASES) {
    it(`root for n=${n} leaves matches the circuit KAT`, async () => {
      const t = await treeOf(n);
      const tsRoot =
        "0x" + t.getRoot().toBigInt().toString(16).padStart(64, "0");
      expect(tsRoot).toBe(root);
    });
  }

  it("getMerklePath returns a full depth-32 path at a deep index", async () => {
    const t = await treeOf(40);
    expect(t.getMerklePath(39).length).toBe(DEPTH);
  });
});
