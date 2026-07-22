// Off-chain spend-graph tracer over threshold-decryptable notes; reads only public per-leaf data via a
// caller-supplied ChainState + opaque decrypt hook. Derivations reuse the wallet nullifier/note mirrors, which
// track shared/src/note_nullifier.nr and note.nr.

import { Fr } from "@aztec/foundation/fields";
import { Point } from "../tss/bjj.js";
import { computePsi, computeNullifier } from "../note/nullifier.js";
import { unpackParents, PARENTS_HIDDEN } from "../note/note.js";
import { DEM_FIELDS } from "../crypto/dem.js";

// parents is the last DEM field; psi is re-derived from CEK, never transmitted.
const PARENTS_FIELD_INDEX = DEM_FIELDS - 1;

export interface LeafData {
  ephPub: Point;
  ciphertext: Fr[];
  leaf: Fr;
}

/** `childrenOfSpend` returns the leaf indexes created by the tx that spent `nf`. */
export interface ChainState {
  getLeaf(index: number): LeafData | undefined;
  nextLeafIndex(): number;
  isNullifierSpent(nf: Fr): boolean;
  childrenOfSpend(nf: Fr): number[];
}

export type DecryptNote = (
  ephPub: Point,
  ciphertext: Fr[],
) => Promise<{ fields: Fr[]; cek: Fr }>;

/** Edge [p, c] means leaf p was consumed to create leaf c. */
export interface SpendGraph {
  nodes: number[];
  edges: [number, number][];
}

interface Expansion {
  neighbor: number;
  edge: [number, number];
}

type Step = (index: number) => Promise<Expansion[]>;

class GraphBuilder {
  private readonly nodeSet = new Set<number>();
  private readonly edgeKeys = new Set<string>();
  private readonly edgeList: [number, number][] = [];

  addNode(index: number): void {
    this.nodeSet.add(index);
  }

  addEdge(parent: number, child: number): void {
    const key = `${parent}->${child}`;
    if (this.edgeKeys.has(key)) return;
    this.edgeKeys.add(key);
    this.edgeList.push([parent, child]);
  }

  build(): SpendGraph {
    return {
      nodes: [...this.nodeSet].sort((a, b) => a - b),
      edges: [...this.edgeList].sort((a, b) => a[0] - b[0] || a[1] - b[1]),
    };
  }
}

function assertInRange(index: number, chain: ChainState): void {
  const n = chain.nextLeafIndex();
  if (!Number.isInteger(index) || index < 0 || index >= n) {
    throw new Error(`chainTrace: leaf index ${index} out of range [0, ${n})`);
  }
}

// Visited-set worklist: terminates even on a cyclic spend graph.
async function traverse(
  start: number,
  chain: ChainState,
  step: Step,
): Promise<SpendGraph> {
  assertInRange(start, chain);
  const graph = new GraphBuilder();
  const visited = new Set<number>();
  const worklist: number[] = [start];
  while (worklist.length > 0) {
    const index = worklist.pop();
    if (index === undefined) break;
    if (visited.has(index)) continue;
    visited.add(index);
    graph.addNode(index);
    for (const { neighbor, edge } of await step(index)) {
      graph.addEdge(edge[0], edge[1]);
      if (!visited.has(neighbor)) worklist.push(neighbor);
    }
  }
  return graph.build();
}

// slot1 (high 32 bits) == 0 marks a single-input spend (only slot0 real); nonzero slot1 means both are real
// (a join, canonical index_a < index_b). The caller handles packed == 0 (a deposit) first.
function consumedLeaves(packed: Fr): number[] {
  const [p0, p1] = unpackParents(packed);
  if (p1.leafIndex === 0) return [p0.leafIndex];
  return [p0.leafIndex, p1.leafIndex];
}

export async function forwardTrace(
  startLeafIndex: number,
  chain: ChainState,
  decrypt: DecryptNote,
): Promise<SpendGraph> {
  const step: Step = async (index) => {
    const leaf = chain.getLeaf(index);
    if (leaf === undefined) return [];
    const { cek } = await decrypt(leaf.ephPub, leaf.ciphertext);
    const psi = await computePsi(cek);
    const nf = await computeNullifier(psi, new Fr(BigInt(index)));
    if (!chain.isNullifierSpent(nf)) return [];
    const expansions: Expansion[] = [];
    for (const child of chain.childrenOfSpend(nf)) {
      assertInRange(child, chain);
      expansions.push({ neighbor: child, edge: [index, child] });
    }
    return expansions;
  };
  return traverse(startLeafIndex, chain, step);
}

export async function backwardTrace(
  startLeafIndex: number,
  chain: ChainState,
  decrypt: DecryptNote,
): Promise<SpendGraph> {
  const step: Step = async (index) => {
    const leaf = chain.getLeaf(index);
    if (leaf === undefined) return [];
    const { fields } = await decrypt(leaf.ephPub, leaf.ciphertext);
    if (fields.length < DEM_FIELDS) {
      throw new Error(
        `chainTrace: decrypt returned ${fields.length} fields, need >= ${DEM_FIELDS} (parents at index ${PARENTS_FIELD_INDEX})`,
      );
    }
    const packed = fields[PARENTS_FIELD_INDEX];
    if (packed.toBigInt() === 0n) return [];
    // parents == PARENTS_HIDDEN: source not encoded here; compliance recovers it via tx-grouping, so the
    // parents-based backward trace terminates rather than unpacking the sentinel as a real index pack.
    if (packed.toBigInt() === PARENTS_HIDDEN.toBigInt()) return [];
    const expansions: Expansion[] = [];
    for (const parent of consumedLeaves(packed)) {
      assertInRange(parent, chain);
      expansions.push({ neighbor: parent, edge: [parent, index] });
    }
    return expansions;
  };
  return traverse(startLeafIndex, chain, step);
}
