// Off-chain chain-tracing overlay for threshold compliance. Once the committee can threshold-decrypt any
// note's CEK (see thresholdCek), the full spend graph is recoverable in BOTH directions with ZERO circuit or
// contract change: the trace reads only public per-leaf data (eph_pub, ciphertext) through a caller-supplied
// ChainState, plus a decrypt hook that is opaque to the trace -- so the same code runs for a single-key holder
// and a (t,n) committee.
//
//   forward:  decrypt -> cek -> psi = Poseidon2([cek, PSI_DOMAIN]) -> nullifier = Poseidon2([psi, leaf_index])
//             -> if spent, expand into the leaves that spend created (childrenOfSpend).
//   backward: decrypt -> read the plaintext parents pointer -> unpack the consumed leaf indexes -> expand into
//             each parent until parents == 0 (a deposit / public-claim root).
//
// Derivations mirror shared/src/note_nullifier.nr and note.nr EXACTLY (parity is load-bearing); reuse the
// wallet mirrors so a formula change in one place is a compile break here.

import { Fr } from "@aztec/foundation/fields";
import { Point } from "../tss/bjj.js";
import { computePsi, computeNullifier } from "../note/nullifier.js";
import { unpackParents } from "../note/note.js";
import { DEM_FIELDS } from "../crypto/dem.js";

// parents is the last of the 7 transmitted DEM fields, order [note_version, asset_id, note_type,
// conditions_hash, value, owner, parents]; psi is re-derived from CEK, never transmitted.
const PARENTS_FIELD_INDEX = DEM_FIELDS - 1;

/** Public per-leaf data an indexer exposes; the trace never needs a private witness. */
export interface LeafData {
  ephPub: Point;
  ciphertext: Fr[];
  leaf: Fr;
}

/** Read-only chain view the caller provides, keeping the trace off any live node. `childrenOfSpend` returns
 *  the leaf indexes created by the transaction that spent `nf` (its output notes). */
export interface ChainState {
  getLeaf(index: number): LeafData | undefined;
  nextLeafIndex(): number;
  isNullifierSpent(nf: Fr): boolean;
  childrenOfSpend(nf: Fr): number[];
}

/** Decrypt hook: single-key or threshold, opaque to the trace. Returns the DEM plaintext fields (canonical
 *  7-field order) plus the recovered CEK. */
export type DecryptNote = (
  ephPub: Point,
  ciphertext: Fr[],
) => Promise<{ fields: Fr[]; cek: Fr }>;

/** Directed spend graph. An edge [p, c] means leaf p was consumed to create leaf c (value flows p -> c);
 *  both traces use this orientation, so a forward and a backward result compose directly. */
export interface SpendGraph {
  nodes: number[];
  edges: [number, number][];
}

// One reachable leaf plus the edges it contributes; `neighbor` is the leaf to expand into next.
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

// Iterative worklist keyed by a visited-set: guarantees termination even if an indexer reports a cyclic
// spend graph, and avoids deep-recursion stack overflow on long chains. Every edge is recorded before the
// visited check, so an edge into an already-seen leaf is still captured exactly once (GraphBuilder dedupes).
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

// Split a packed parents pointer into the leaf indexes actually consumed. slot1 (high 32 bits) == 0 marks a
// single-input spend (transfer/split/withdraw pad the high slot with 0), so only slot0 is real; a join always
// carries slot1 = index_b >= 1 (canonical index_a < index_b), so a nonzero slot1 means both slots are real.
// The caller handles packed == 0 (a deposit) before reaching here, so slot0 is guaranteed nonzero when
// slot1 == 0.
function consumedLeaves(packed: Fr): number[] {
  const [p0, p1] = unpackParents(packed);
  if (p1.leafIndex === 0) return [p0.leafIndex];
  return [p0.leafIndex, p1.leafIndex];
}

/** Forward trace: from `startLeafIndex`, follow each note's nullifier to the leaves its spend created and
 *  recurse, yielding the descendant spend graph. Unknown or unspent leaves are graph frontiers. */
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

/** Backward trace: from `startLeafIndex`, read the note's plaintext parents pointer, unpack the consumed
 *  leaf indexes, and recurse until a note with parents == 0 (a deposit / public-claim root), yielding the
 *  ancestor lineage graph. */
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
    const expansions: Expansion[] = [];
    for (const parent of consumedLeaves(packed)) {
      assertInRange(parent, chain);
      expansions.push({ neighbor: parent, edge: [parent, index] });
    }
    return expansions;
  };
  return traverse(startLeafIndex, chain, step);
}
