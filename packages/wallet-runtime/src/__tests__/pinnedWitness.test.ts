import { beforeAll, describe, expect, it } from "vitest";
import { Fr } from "@aztec/foundation/fields";
import { leaf } from "@hisoka/wallets";
import type { TreeState } from "../chain/chainReader.js";
import type { TreeWitness, WitnessPort } from "../discovery/ports.js";
import { WalletRuntimeError } from "../errors.js";
import {
  checkedWitness,
  pinnedWitnessSource,
  type WitnessChecks,
} from "../spend/pinnedWitness.js";
import {
  LeafListWitnessPort,
  note,
  poolLeaves,
  treeOf,
} from "./fixtures/tree.js";

let leaves: Fr[];
let pin: TreeState;

beforeAll(async () => {
  leaves = await poolLeaves(5);
  const tree = await treeOf(leaves);
  pin = {
    leafCount: leaves.length,
    root: tree.getRoot(),
    block: { number: 10, hash: `0x${"0a".repeat(32)}`, timestamp: 1n },
  };
});

function checksOver(
  witnesses: WitnessPort,
  known: (root: Fr) => boolean = () => true,
  log: string[] = [],
): WitnessChecks {
  return {
    witnesses: {
      witness: async (i, n) => {
        log.push("witness");
        return witnesses.witness(i, n);
      },
    },
    chain: {
      isKnownRoot: async (root) => {
        log.push("isKnownRoot");
        return known(root);
      },
    },
  };
}

async function codeOf(p: Promise<unknown>): Promise<string> {
  const err = await p.then(
    () => undefined,
    (e: unknown) => e,
  );
  expect(err).toBeInstanceOf(WalletRuntimeError);
  return (err as WalletRuntimeError).code;
}

function tampered(
  port: WitnessPort,
  edit: (w: TreeWitness) => TreeWitness,
): WitnessPort {
  return { witness: async (i, n) => edit(await port.witness(i, n)) };
}

describe("pinned witness checks", () => {
  it("accepts a path that names the note, folds to the pinned root, and is known on chain", async () => {
    const w = await checkedWitness(
      checksOver(new LeafListWitnessPort(leaves)),
      pin,
      {
        leafIndex: 3,
        commitment: leaves[3]!,
      },
    );
    expect(w.root.equals(pin.root)).toBe(true);
    expect(w.siblings).toHaveLength(32);
  });

  it("rejects a tree leaf that is not the stored note", async () => {
    const other = await leaf(note(99n));
    const checks = checksOver(new LeafListWitnessPort(leaves));
    expect(
      await codeOf(
        checkedWitness(checks, pin, { leafIndex: 3, commitment: other }),
      ),
    ).toBe("LEAF_MISMATCH");
  });

  it("rejects a path for another index or tree size", async () => {
    const port = new LeafListWitnessPort(leaves);
    const shifted = tampered(port, (w) => ({
      ...w,
      leafCount: w.leafCount + 1,
    }));
    expect(
      await codeOf(
        checkedWitness(checksOver(shifted), pin, {
          leafIndex: 2,
          commitment: leaves[2]!,
        }),
      ),
    ).toBe("WITNESS_MISMATCH");
  });

  it("rejects a path that does not fold to its own root", async () => {
    const port = new LeafListWitnessPort(leaves);
    const bent = tampered(port, (w) => ({
      ...w,
      siblings: w.siblings.map((s, i) =>
        i === 0 ? new Fr(s.toBigInt() + 1n) : s,
      ),
    }));
    expect(
      await codeOf(
        checkedWitness(checksOver(bent), pin, {
          leafIndex: 2,
          commitment: leaves[2]!,
        }),
      ),
    ).toBe("WITNESS_MISMATCH");
  });

  it("rejects a consistent path from another fork's tree", async () => {
    const fork = [...leaves.slice(0, leaves.length - 1), await leaf(note(77n))];
    const forkPort = new LeafListWitnessPort(fork);
    expect(
      await codeOf(
        checkedWitness(checksOver(forkPort), pin, {
          leafIndex: 2,
          commitment: leaves[2]!,
        }),
      ),
    ).toBe("ROOT_PIN_MISMATCH");
  });

  it("rejects a note outside the pinned tree", async () => {
    const checks = checksOver(new LeafListWitnessPort(leaves));
    expect(
      await codeOf(
        checkedWitness(checks, pin, {
          leafIndex: pin.leafCount,
          commitment: leaves[1]!,
        }),
      ),
    ).toBe("WITNESS_MISMATCH");
    expect(
      await codeOf(
        checkedWitness(checks, pin, { leafIndex: 0, commitment: leaves[0]! }),
      ),
    ).toBe("WITNESS_MISMATCH");
  });

  it("stops at ROOT_UNKNOWN before assembly can hand the path to the prover", async () => {
    const run = async (known: boolean): Promise<string[]> => {
      const log: string[] = [];
      const source = pinnedWitnessSource(
        checksOver(new LeafListWitnessPort(leaves), () => known, log),
        pin,
        new Map([[4, leaves[4]!]]),
      );
      try {
        await source.witnessFor(leaves[4]!, 4);
        log.push("prove");
      } catch (e) {
        log.push((e as WalletRuntimeError).code);
      }
      return log;
    };
    expect(await run(true)).toEqual(["witness", "isKnownRoot", "prove"]);
    expect(await run(false)).toEqual([
      "witness",
      "isKnownRoot",
      "ROOT_UNKNOWN",
    ]);
  });

  it("refuses a leaf the plan did not lease", async () => {
    const source = pinnedWitnessSource(
      checksOver(new LeafListWitnessPort(leaves)),
      pin,
      new Map([[4, leaves[4]!]]),
    );
    expect(await codeOf(source.witnessFor(leaves[3]!, 3))).toBe(
      "LEAF_MISMATCH",
    );
    expect(await codeOf(source.witnessFor(leaves[3]!, 4))).toBe(
      "LEAF_MISMATCH",
    );
  });

  it("takes both join witnesses at the pinned size while the live tree grows", async () => {
    const live = [...leaves];
    const port = new LeafListWitnessPort(live);
    const source = pinnedWitnessSource(
      checksOver(port),
      pin,
      new Map([
        [2, leaves[2]!],
        [5, leaves[5]!],
      ]),
    );
    const first = await source.witnessFor(leaves[2]!, 2);
    live.push(await leaf(note(50n)), await leaf(note(51n)));
    const second = await source.witnessFor(leaves[5]!, 5);

    expect(port.requests.map((r) => r.leafCount)).toEqual([
      pin.leafCount,
      pin.leafCount,
    ]);
    expect(first.root.equals(second.root)).toBe(true);
    expect(second.root.equals(pin.root)).toBe(true);
  });
});
