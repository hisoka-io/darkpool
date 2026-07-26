// Off-chain spend-graph tracer over threshold-decryptable notes; reads public per-leaf data via a caller-supplied ChainState.

import { Fr } from "@aztec/foundation/fields";
import { Point } from "../tss/bjj.js";
import { computePsi, computeNullifier } from "../note/nullifier.js";
import {
  leaf as computeLeaf,
  unpackParents,
  PARENTS_HIDDEN,
} from "../note/note.js";
import { DEM_FIELDS } from "../crypto/dem.js";

// parents is the last DEM field; psi is re-derived from CEK, never transmitted.
const PARENTS_FIELD_INDEX = DEM_FIELDS - 1;
const TWO_POW_128 = 1n << 128n;
const TWO_POW_64 = 1n << 64n;

// ChainState and its decrypt hook are UNTRUSTED; rebuilt-leaf == on-chain-commitment is what stops a tampered ciphertext inventing a lineage.
async function openLeaf(
  data: LeafData,
  decrypt: DecryptNote,
): Promise<{ fields: Fr[]; psi: Fr } | null> {
  const { fields, cek } = await decrypt(data.ephPub, data.ciphertext);
  if (fields.length < DEM_FIELDS) return null;
  // A tampered ciphertext decrypts to a uniform Fr, which overflows u128 with probability ~1, so this range
  // check runs FIRST or `leaf()` throws and the commitment comparison below never executes.
  if (fields[4].toBigInt() >= TWO_POW_128) return null;
  const psi = await computePsi(cek);
  const rebuilt = await computeLeaf({
    noteVersion: fields[0],
    assetId: fields[1],
    noteType: fields[2],
    conditionsHash: fields[3],
    value: fields[4].toBigInt(),
    owner: fields[5],
    psi,
    parents: fields[PARENTS_FIELD_INDEX],
  });
  return rebuilt.equals(data.leaf) ? { fields, psi } : null;
}

export interface LeafData {
  ephPub: Point;
  ciphertext: Fr[];
  leaf: Fr;
}

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

export interface SpendGraph {
  nodes: number[];
  edges: [number, number][];
  truncated: number[];
}

interface Expansion {
  neighbor: number;
  edge: [number, number];
}

interface StepResult {
  expansions: Expansion[];
  truncated?: boolean;
}

type Step = (index: number) => Promise<StepResult>;

class GraphBuilder {
  private readonly nodeSet = new Set<number>();
  private readonly edgeKeys = new Set<string>();
  private readonly edgeList: [number, number][] = [];
  private readonly truncatedSet = new Set<number>();

  addNode(index: number): void {
    this.nodeSet.add(index);
  }

  addTruncated(index: number): void {
    this.truncatedSet.add(index);
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
      truncated: [...this.truncatedSet].sort((a, b) => a - b),
    };
  }
}

function assertInRange(index: number, chain: ChainState): void {
  const n = chain.nextLeafIndex();
  if (!Number.isInteger(index) || index < 0 || index >= n) {
    throw new Error(`chainTrace: leaf index ${index} out of range [0, ${n})`);
  }
}

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
    const { expansions, truncated } = await step(index);
    if (truncated === true) graph.addTruncated(index);
    for (const { neighbor, edge } of expansions) {
      graph.addEdge(edge[0], edge[1]);
      if (!visited.has(neighbor)) worklist.push(neighbor);
    }
  }
  return graph.build();
}

// slot1 (high 32 bits) == 0 marks a single-input spend; nonzero slot1 is a join (canonical index_a < index_b).
// Returns null rather than throwing on an unpackable field: callers route that through `truncated` so one
// corrupt leaf yields a partial graph instead of aborting the whole trace.
function consumedLeaves(packed: Fr, chain: ChainState): number[] | null {
  if (packed.toBigInt() >= TWO_POW_64) return null;
  const [p0, p1] = unpackParents(packed);
  const indexes =
    p1.leafIndex === 0 ? [p0.leafIndex] : [p0.leafIndex, p1.leafIndex];
  const n = chain.nextLeafIndex();
  return indexes.every((i) => i >= 0 && i < n) ? indexes : null;
}

export async function forwardTrace(
  startLeafIndex: number,
  chain: ChainState,
  decrypt: DecryptNote,
): Promise<SpendGraph> {
  const step: Step = async (index) => {
    const leafData = chain.getLeaf(index);
    if (leafData === undefined) return { expansions: [], truncated: true };
    const opened = await openLeaf(leafData, decrypt);
    if (opened === null) return { expansions: [], truncated: true };
    const nf = await computeNullifier(opened.psi, new Fr(BigInt(index)));
    if (!chain.isNullifierSpent(nf)) return { expansions: [] };
    const children = chain.childrenOfSpend(nf);
    const n = chain.nextLeafIndex();
    if (children.some((c) => c < 0 || c >= n))
      return { expansions: [], truncated: true };
    const expansions: Expansion[] = children.map((child) => ({
      neighbor: child,
      edge: [index, child] as [number, number],
    }));
    return { expansions, truncated: expansions.length === 0 };
  };
  return traverse(startLeafIndex, chain, step);
}

// A transfer memo hides `parents`; the sender's change note is the co-output of the same atomic tx (memo first,
// change next) and carries the real parents. That adjacency is unproven, so the parent's nullifier MUST be spent.
async function bridgeHiddenParents(
  memoIndex: number,
  chain: ChainState,
  decrypt: DecryptNote,
): Promise<Fr | null> {
  const sibling = chain.getLeaf(memoIndex + 1);
  if (sibling === undefined) return null;

  const openedSibling = await openLeaf(sibling, decrypt);
  if (openedSibling === null) return null;
  const packed = openedSibling.fields[PARENTS_FIELD_INDEX];
  const value = packed.toBigInt();
  if (value === 0n || value === PARENTS_HIDDEN.toBigInt()) return null;

  const parents = consumedLeaves(packed, chain);
  if (parents === null) return null;

  for (const parent of parents) {
    const parentLeaf = chain.getLeaf(parent);
    if (parentLeaf === undefined) return null;
    const openedParent = await openLeaf(parentLeaf, decrypt);
    if (openedParent === null) return null;
    const nf = await computeNullifier(openedParent.psi, new Fr(BigInt(parent)));
    // Spent SOMEWHERE is not enough: the sibling may belong to a different tx, whose parents would then be
    // attributed to this memo. Requiring the memo among the spend's outputs is what proves the shared tx.
    if (!chain.childrenOfSpend(nf).includes(memoIndex)) return null;
  }
  return packed;
}

export async function backwardTrace(
  startLeafIndex: number,
  chain: ChainState,
  decrypt: DecryptNote,
): Promise<SpendGraph> {
  const expand = (index: number, packed: Fr): StepResult => {
    const parents = consumedLeaves(packed, chain);
    if (parents === null) return { expansions: [], truncated: true };
    return {
      expansions: parents.map((parent) => ({
        neighbor: parent,
        edge: [parent, index] as [number, number],
      })),
    };
  };

  const step: Step = async (index) => {
    const leafData = chain.getLeaf(index);
    if (leafData === undefined) return { expansions: [], truncated: true };
    const opened = await openLeaf(leafData, decrypt);
    if (opened === null) return { expansions: [], truncated: true };
    const packed = opened.fields[PARENTS_FIELD_INDEX];
    if (packed.toBigInt() === 0n) return { expansions: [] };
    if (packed.toBigInt() === PARENTS_HIDDEN.toBigInt()) {
      const bridged = await bridgeHiddenParents(index, chain, decrypt);
      return bridged === null
        ? { expansions: [], truncated: true }
        : expand(index, bridged);
    }
    return expand(index, packed);
  };
  return traverse(startLeafIndex, chain, step);
}
