import { Fr } from "@aztec/foundation/fields";
import {
  leaf,
  LeanIMT,
  newSeededTree,
  NOTE_TYPE_STANDARD,
  NOTE_VERSION,
  TREE_DEPTH,
  type Note,
} from "@hisoka/wallets";
import type { TreeWitness, WitnessPort } from "../../discovery/ports.js";

export const CHAIN_ID = 31337n;

export function note(seed: bigint): Note {
  return {
    noteVersion: NOTE_VERSION,
    assetId: new Fr(0xa11ce0000n + seed),
    noteType: new Fr(NOTE_TYPE_STANDARD),
    conditionsHash: new Fr(0n),
    value: 1_000n + seed,
    owner: new Fr(0xb0bn + seed),
    psi: new Fr(0x5eedn + seed),
    parents: new Fr(0n),
  };
}

/** A seeded pool tree (genesis at 0) holding `count` real note leaves at 1..count. */
export async function poolLeaves(count: number): Promise<Fr[]> {
  const tree = await newSeededTree(CHAIN_ID);
  const leaves = [...(tree.levels[0] ?? [])];
  for (let i = 1; i <= count; i++) leaves.push(await leaf(note(BigInt(i))));
  return leaves;
}

export async function treeOf(leaves: readonly Fr[]): Promise<LeanIMT> {
  const tree = new LeanIMT(TREE_DEPTH);
  for (const l of leaves) await tree.insert(l);
  return tree;
}

/**
 * A witness port over a growing leaf list. Answers for any historical size by rebuilding that prefix, the
 * way a self-index answers a size it does not keep a tree for. Records every request.
 */
export class LeafListWitnessPort implements WitnessPort {
  readonly requests: { leafIndex: number; leafCount: number }[] = [];
  constructor(readonly leaves: Fr[]) {}

  async witness(leafIndex: number, leafCount: number): Promise<TreeWitness> {
    this.requests.push({ leafIndex, leafCount });
    const tree = await treeOf(this.leaves.slice(0, leafCount));
    return {
      leafIndex,
      leafCount,
      leaf: this.leaves[leafIndex]!,
      siblings: tree.getMerklePath(leafIndex),
      root: tree.getRoot(),
    };
  }
}
