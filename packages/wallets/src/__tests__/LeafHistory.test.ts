import { describe, it, expect, beforeAll } from "vitest";
import { Fr } from "@aztec/foundation/fields";
import { LeanIMT } from "../merkle/LeanIMT.js";
import { TREE_DEPTH, genesisLeaf } from "../merkle/genesis.js";
import {
  LeafHistory,
  LeafHistoryError,
  type LeafInsertedLog,
} from "../merkle/LeafHistory.js";
import { foldPath } from "../tx/witnessSources.js";
import { toFr } from "../crypto/fields.js";

const LEAF_COUNT = 21;

/** The LeafInserted logs a pool would emit for `leaves`, roots taken from an independent LeanIMT. */
async function logsFor(leaves: readonly Fr[]): Promise<LeafInsertedLog[]> {
  const t = new LeanIMT(TREE_DEPTH);
  const logs: LeafInsertedLog[] = [];
  for (let i = 0; i < leaves.length; i++) {
    const newRoot = await t.insert(leaves[i]!);
    logs.push({ leafIndex: BigInt(i), leaf: leaves[i]!, newRoot });
  }
  return logs;
}

async function rebuiltPath(
  leaves: readonly Fr[],
  index: number,
  size: number,
): Promise<Fr[]> {
  const t = new LeanIMT(TREE_DEPTH);
  for (const leaf of leaves.slice(0, size)) await t.insert(leaf);
  return t.getMerklePath(index);
}

async function expectReason(
  fn: () => unknown,
  reason: LeafHistoryError["reason"],
): Promise<void> {
  try {
    await fn();
  } catch (e) {
    expect(e).toBeInstanceOf(LeafHistoryError);
    expect((e as LeafHistoryError).reason).toBe(reason);
    return;
  }
  throw new Error(`expected LeafHistoryError ${reason}`);
}

describe("LeafHistory (solver tree at a historical size)", () => {
  let leaves: Fr[];
  let logs: LeafInsertedLog[];
  let history: LeafHistory;

  beforeAll(async () => {
    leaves = [await genesisLeaf(31337n)];
    for (let i = 1; i < LEAF_COUNT; i++) leaves.push(toFr(0x1000n + BigInt(i)));
    logs = await logsFor(leaves);
    history = await LeafHistory.fromLogs(logs);
  });

  it("every path at every historical size folds to that size's logged root and equals a rebuild of the first n leaves", async () => {
    expect(history.size).toBe(LEAF_COUNT);
    for (let size = 1; size <= LEAF_COUNT; size++) {
      for (let i = 0; i < size; i++) {
        const { siblings, root } = await history.pathAt(i, size);
        expect(root.equals(logs[size - 1]!.newRoot)).toBe(true);
        expect(
          (await foldPath(leaves[i]!, i, siblings)).equals(
            logs[size - 1]!.newRoot,
          ),
        ).toBe(true);
        const rebuilt = await rebuiltPath(leaves, i, size);
        expect(siblings.map((s) => s.toString())).toEqual(
          rebuilt.map((s) => s.toString()),
        );
      }
    }
  });

  it("a historical path differs from the current tree's path once a later leaf fills a sibling", async () => {
    const current = new LeanIMT(TREE_DEPTH);
    for (const leaf of leaves) await current.insert(leaf);
    const { siblings } = await history.pathAt(4, 5);
    expect(siblings[0]!.equals(new Fr(0n))).toBe(true);
    expect(current.getMerklePath(4)[0]!.equals(leaves[5]!)).toBe(true);
    expect(
      (await foldPath(leaves[4]!, 4, current.getMerklePath(4))).equals(
        logs[4]!.newRoot,
      ),
    ).toBe(false);
  });

  it("maps each logged root to its size, and refuses an unknown root or a mismatched hint", async () => {
    logs.forEach((log, i) => {
      expect(history.sizeAt(log.newRoot)).toBe(i + 1);
      expect(history.resolveSize(log.newRoot, i + 1)).toBe(i + 1);
    });
    expect(history.sizeAt(toFr(12345n))).toBeUndefined();
    await expectReason(
      () => history.resolveSize(toFr(12345n), 3),
      "UNKNOWN_ROOT",
    );
    await expectReason(
      () => history.resolveSize(logs[6]!.newRoot, 8),
      "SIZE_HINT_MISMATCH",
    );
  });

  it("rejects a maker index at or above the size, and a size the history never had", async () => {
    await expectReason(() => history.pathAt(7, 7), "INDEX_NOT_BELOW_SIZE");
    await expectReason(() => history.pathAt(20, 7), "INDEX_NOT_BELOW_SIZE");
    await expectReason(() => history.pathAt(-1, 7), "INDEX_NOT_BELOW_SIZE");
    await expectReason(() => history.pathAt(0, 0), "SIZE_OUT_OF_RANGE");
    await expectReason(
      () => history.pathAt(0, LEAF_COUNT + 1),
      "SIZE_OUT_OF_RANGE",
    );
  });

  it("refuses a gapped log list and a log whose newRoot was not produced by its leaf", async () => {
    await expectReason(
      () => LeafHistory.fromLogs([logs[0]!, logs[2]!]),
      "LOG_GAP",
    );
    const forged = logs.slice(0, 4).map((l) => ({ ...l }));
    forged[3] = { ...forged[3]!, newRoot: logs[2]!.newRoot };
    await expectReason(() => LeafHistory.fromLogs(forged), "ROOT_MISMATCH");
  });

  it("reproduces the root the on-chain pool reached in the Kage golden fixture", async () => {
    // [genesis(31337), leaf_A, leaf_B]: the tree the committed swap_settle proof was proven against, and whose
    // root a deployed DarkPool reaches after the same two inserts.
    const golden = await logsFor([
      await genesisLeaf(31337n),
      Fr.fromString(
        "0x28be7bbf15a290be8537d34ec7427b0350bdee1db99d28bc0ec8b4149a4f16b1",
      ),
      Fr.fromString(
        "0x1c5167bdcfe8209e3d647bfa2ac08351d4149c414c84fe36825a3c0d7cc04b3b",
      ),
    ]);
    const h = await LeafHistory.fromLogs(golden);
    const goldenRoot = Fr.fromString(
      "0x02f41bedcc622998ffab5b079d4ad43e119eb580b9c91b70d04fa2d00160b9b3",
    );
    expect(h.resolveSize(goldenRoot, 3)).toBe(3);
    expect((await h.pathAt(2, 3)).root.equals(goldenRoot)).toBe(true);
  });
});
