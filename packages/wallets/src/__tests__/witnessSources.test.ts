import { describe, it, expect } from "vitest";
import { Fr } from "@aztec/foundation/fields";
import { toFr } from "../crypto/fields.js";
import { newSeededTree } from "../merkle/genesis.js";
import {
  LocalTreeWitnessSource,
  IndexerWitnessSource,
  WitnessSourceError,
  foldPath,
} from "../tx/witnessSources.js";

const CHAIN = 31337n;

async function treeWith(leaves: Fr[]) {
  const t = await newSeededTree(CHAIN);
  for (const l of leaves) await t.insert(l);
  return t;
}

describe("LocalTreeWitnessSource", () => {
  it("returns a witness that folds back to the tree root", async () => {
    const leaves = [toFr(11n), toFr(22n), toFr(33n)];
    const tree = await treeWith(leaves);
    const src = new LocalTreeWitnessSource(tree);

    const w = await src.witnessFor(toFr(22n));
    // Genesis occupies index 0, so the second inserted note sits at index 2.
    expect(w.leafIndex).toBe(2);
    expect(await foldPath(toFr(22n), w.leafIndex, w.siblings)).toStrictEqual(
      w.root,
    );
    expect(w.root).toStrictEqual(tree.getRoot());
  });

  it("fails CLOSED for a leaf it has not synced", async () => {
    const src = new LocalTreeWitnessSource(await treeWith([toFr(11n)]));
    await expect(src.witnessFor(toFr(999n))).rejects.toThrow(
      WitnessSourceError,
    );
  });
});

describe("IndexerWitnessSource", () => {
  /** Serve honest witnesses out of a real local tree, as a correct indexer would. */
  async function honestTransport(leaves: Fr[]) {
    const tree = await treeWith(leaves);
    const local = new LocalTreeWitnessSource(tree);
    return async (leafHex: string) => {
      const w = await local.witnessFor(Fr.fromString(leafHex));
      return {
        leafIndex: w.leafIndex,
        siblings: w.siblings.map((s) => s.toString()),
        root: w.root.toString(),
      };
    };
  }

  it("accepts an honest witness", async () => {
    const src = new IndexerWitnessSource(
      await honestTransport([toFr(11n), toFr(22n)]),
    );
    const w = await src.witnessFor(toFr(22n));
    expect(await foldPath(toFr(22n), w.leafIndex, w.siblings)).toStrictEqual(
      w.root,
    );
  });

  // The property the whole untrusted-source design rests on. A hostile indexer can refuse to answer; what it
  // must not be able to do is hand back a witness the wallet builds a proof on.
  it("REJECTS a witness whose siblings do not reproduce its own claimed root", async () => {
    const honest = await honestTransport([toFr(11n), toFr(22n)]);
    const hostile = async (leafHex: string) => {
      const w = await honest(leafHex);
      // Tamper with one sibling while keeping the advertised root.
      const siblings = [...w.siblings];
      siblings[0] = toFr(0xdeadn).toString();
      return { ...w, siblings };
    };
    const src = new IndexerWitnessSource(hostile);
    await expect(src.witnessFor(toFr(22n))).rejects.toMatchObject({
      reason: "ROOT_MISMATCH",
    });
  });

  it("REJECTS a relocated index, which is what CRIT-001 exploited", async () => {
    const honest = await honestTransport([toFr(11n), toFr(22n)]);
    const relocating = async (leafHex: string) => {
      const w = await honest(leafHex);
      // Same siblings, different index. Before the level was absorbed into the tree hash this reproduced
      // the identical root and minted a second nullifier for one note.
      return { ...w, leafIndex: w.leafIndex + 4 };
    };
    const src = new IndexerWitnessSource(relocating);
    await expect(src.witnessFor(toFr(22n))).rejects.toMatchObject({
      reason: expect.stringMatching(/ROOT_MISMATCH|MALFORMED_RESPONSE/),
    });
  });

  it("rejects a malformed response rather than passing it on", async () => {
    const src = new IndexerWitnessSource(async () => ({
      leafIndex: 1,
      siblings: ["0x1"],
      root: "0x2",
    }));
    await expect(src.witnessFor(toFr(1n))).rejects.toMatchObject({
      reason: "MALFORMED_RESPONSE",
    });
  });

  it("surfaces a transport failure as a typed error", async () => {
    const src = new IndexerWitnessSource(async () => {
      throw new Error("connection reset");
    });
    await expect(src.witnessFor(toFr(1n))).rejects.toMatchObject({
      reason: "TRANSPORT",
    });
  });
});
