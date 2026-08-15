import { describe, it, expect } from "vitest";
import { LeanIMT } from "../merkle/LeanIMT.js";
import { toFr } from "../crypto/fields.js";

// Parity vs circuit lib.nr kat_leanimt_tri_parity: the 'right-zero-sibling -> parent = left child' lean rule must match both sides.
const DEPTH = 32;

async function treeOf(n: number): Promise<LeanIMT> {
  const t = new LeanIMT(DEPTH);
  for (let i = 1; i <= n; i++) await t.insert(toFr(BigInt(i)));
  return t;
}

const CASES: Array<{ n: number; root: string }> = [
  {
    n: 16,
    root: "0x27785efe80248e9c945c1b2af10d8a8f24d3fedbbaac546e6ce7272206e6cc99",
  },
  {
    n: 17,
    root: "0x09b1b3b74d6b8d08fc8fd03e1d0b1672fe3aecd488d7ed030b91f3fac1456461",
  },
  {
    n: 33,
    root: "0x0e98ae5275a8150809382554f307b2d12a4411de2d2f296f8fecefd091498ca5",
  },
  {
    n: 40,
    root: "0x0c65ee133f15f3e41b526a7c27c8f71545f41a92e096fa35e8552b3937272fa2",
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
