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

    // Genesis occupies index 0, so the second inserted note sits at index 2.
    const w = await src.witnessFor(toFr(22n), 2);
    expect(w.leafIndex).toBe(2);
    expect(await foldPath(toFr(22n), w.leafIndex, w.siblings)).toStrictEqual(
      w.root,
    );
    expect(w.root).toStrictEqual(tree.getRoot());
  });

  it("fails CLOSED for an index it has not synced", async () => {
    const src = new LocalTreeWitnessSource(await treeWith([toFr(11n)]));
    await expect(src.witnessFor(toFr(999n), 2)).rejects.toMatchObject({
      name: "WitnessSourceError",
      reason: "LEAF_NOT_FOUND",
    });
  });

  it("serves each copy of a duplicated leaf at the index the caller expects", async () => {
    const tree = await treeWith([toFr(11n), toFr(22n), toFr(22n)]);
    const src = new LocalTreeWitnessSource(tree);
    for (const index of [2, 3]) {
      const w = await src.witnessFor(toFr(22n), index);
      expect(w.leafIndex).toBe(index);
      expect(await foldPath(toFr(22n), index, w.siblings)).toStrictEqual(
        tree.getRoot(),
      );
    }
  });

  it("refuses an expected index that holds a different leaf", async () => {
    const src = new LocalTreeWitnessSource(
      await treeWith([toFr(11n), toFr(22n)]),
    );
    await expect(src.witnessFor(toFr(22n), 1)).rejects.toMatchObject({
      reason: "LEAF_INDEX_MISMATCH",
    });
  });

  it("refuses an expected index that is not a non-negative integer", async () => {
    const src = new LocalTreeWitnessSource(await treeWith([toFr(11n)]));
    for (const index of [-1, 1.5, Number.NaN]) {
      await expect(src.witnessFor(toFr(11n), index)).rejects.toThrow(
        WitnessSourceError,
      );
      await expect(src.witnessFor(toFr(11n), index)).rejects.toMatchObject({
        reason: "INVALID_LEAF_INDEX",
      });
    }
  });
});

describe("IndexerWitnessSource", () => {
  /** Serve honest witnesses out of a real local tree, as a correct indexer would. */
  async function honestTransport(leaves: Fr[]) {
    const tree = await treeWith(leaves);
    const local = new LocalTreeWitnessSource(tree);
    return async (leafHex: string, leafIndex: number) => {
      const w = await local.witnessFor(Fr.fromString(leafHex), leafIndex);
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
    const w = await src.witnessFor(toFr(22n), 2);
    expect(w.leafIndex).toBe(2);
    expect(await foldPath(toFr(22n), w.leafIndex, w.siblings)).toStrictEqual(
      w.root,
    );
  });

  it("asks the transport for the expected copy of a duplicated leaf", async () => {
    const requested: number[] = [];
    const honest = await honestTransport([toFr(11n), toFr(22n), toFr(22n)]);
    const src = new IndexerWitnessSource(async (leafHex, leafIndex) => {
      requested.push(leafIndex);
      return honest(leafHex, leafIndex);
    });
    const w = await src.witnessFor(toFr(22n), 3);
    expect(requested).toEqual([3]);
    expect(w.leafIndex).toBe(3);
  });

  it("REJECTS a server that answers with the first copy instead of the expected one", async () => {
    const honest = await honestTransport([toFr(11n), toFr(22n), toFr(22n)]);
    const firstMatch = async (leafHex: string) => honest(leafHex, 2);
    const src = new IndexerWitnessSource(firstMatch);
    await expect(src.witnessFor(toFr(22n), 3)).rejects.toMatchObject({
      reason: "LEAF_INDEX_MISMATCH",
    });
  });

  // The property the whole untrusted-source design rests on. A hostile indexer can refuse to answer; what it
  // must not be able to do is hand back a witness the wallet builds a proof on.
  it("REJECTS a witness whose siblings do not reproduce its own claimed root", async () => {
    const honest = await honestTransport([toFr(11n), toFr(22n)]);
    const hostile = async (leafHex: string, leafIndex: number) => {
      const w = await honest(leafHex, leafIndex);
      // Tamper with one sibling while keeping the advertised root.
      const siblings = [...w.siblings];
      siblings[0] = toFr(0xdeadn).toString();
      return { ...w, siblings };
    };
    const src = new IndexerWitnessSource(hostile);
    await expect(src.witnessFor(toFr(22n), 2)).rejects.toMatchObject({
      reason: "ROOT_MISMATCH",
    });
  });

  it("rejects siblings relocated to another index, so one note cannot fold to a second index", async () => {
    const honest = await honestTransport([toFr(11n), toFr(22n)]);
    const relocating = async (leafHex: string, leafIndex: number) => {
      // The real copy's siblings, served for an index four places away. Before the level was absorbed into
      // the tree hash this reproduced the identical root and minted a second nullifier for one note.
      const w = await honest(leafHex, leafIndex - 4);
      return { ...w, leafIndex };
    };
    const src = new IndexerWitnessSource(relocating);
    await expect(src.witnessFor(toFr(22n), 6)).rejects.toMatchObject({
      reason: expect.stringMatching(/ROOT_MISMATCH|MALFORMED_RESPONSE/),
    });
  });

  it("rejects a malformed response rather than passing it on", async () => {
    const src = new IndexerWitnessSource(async () => ({
      leafIndex: 1,
      siblings: ["0x1"],
      root: "0x2",
    }));
    await expect(src.witnessFor(toFr(1n), 1)).rejects.toMatchObject({
      reason: "MALFORMED_RESPONSE",
    });
  });

  it("surfaces a transport failure as a typed error", async () => {
    const src = new IndexerWitnessSource(async () => {
      throw new Error("connection reset");
    });
    await expect(src.witnessFor(toFr(1n), 1)).rejects.toMatchObject({
      reason: "TRANSPORT",
    });
  });
});
