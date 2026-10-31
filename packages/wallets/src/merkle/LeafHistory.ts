import { Fr } from "@aztec/foundation/fields";
import { Poseidon } from "../crypto/Poseidon.js";
import { toFr } from "../crypto/fields.js";
import { foldPath } from "../tx/witnessSources.js";
import { LeanIMT } from "./LeanIMT.js";
import { TREE_DEPTH } from "./genesis.js";

/** One decoded `LeafInserted(uint256 indexed leafIndex, bytes32 leaf, bytes32 newRoot)` log. */
export interface LeafInsertedLog {
  readonly leafIndex: bigint;
  readonly leaf: Fr;
  readonly newRoot: Fr;
}

export class LeafHistoryError extends Error {
  constructor(
    readonly reason:
      | "LOG_GAP"
      | "ZERO_LEAF"
      | "TREE_FULL"
      | "ROOT_MISMATCH"
      | "UNKNOWN_ROOT"
      | "SIZE_HINT_MISMATCH"
      | "SIZE_OUT_OF_RANGE"
      | "INDEX_NOT_BELOW_SIZE",
    message: string,
  ) {
    super(message);
    this.name = "LeafHistoryError";
  }
}

const ZERO = new Fr(0n);

/**
 * The pool's tree at every size it has had, rebuilt from `LeafInserted` logs. A Kage solver proves against the
 * taker's root, which is the root at some historical size `n`; the maker's input note must sit below `n` and its
 * path must be the one in the tree of exactly `n` leaves, not the current tree (a right sibling that was empty
 * at `n` may be filled now).
 *
 * Every log's `newRoot` is recomputed while building, so a gapped, reordered or forged log list is refused
 * instead of producing paths that fail in the prover.
 */
export class LeafHistory {
  private constructor(
    private readonly tree: LeanIMT,
    private readonly rootBySize: readonly Fr[],
    private readonly sizeByRoot: ReadonlyMap<bigint, number>,
  ) {}

  /** Build from every `LeafInserted` log of the pool, starting at the genesis leaf (index 0), in index order. */
  static async fromLogs(
    logs: readonly LeafInsertedLog[],
    depth: number = TREE_DEPTH,
  ): Promise<LeafHistory> {
    const tree = new LeanIMT(depth);
    const rootBySize: Fr[] = [];
    const sizeByRoot = new Map<bigint, number>();
    const capacity = 1n << BigInt(depth);
    for (let i = 0; i < logs.length; i++) {
      const log = logs[i]!;
      if (log.leafIndex !== BigInt(i)) {
        throw new LeafHistoryError(
          "LOG_GAP",
          `LeafInserted log ${i} carries leafIndex ${log.leafIndex}; logs must be contiguous from index 0`,
        );
      }
      if (log.leaf.isZero()) {
        throw new LeafHistoryError(
          "ZERO_LEAF",
          `LeafInserted log ${i} carries a zero leaf; the pool never inserts one`,
        );
      }
      if (BigInt(i) >= capacity) {
        throw new LeafHistoryError(
          "TREE_FULL",
          `LeafInserted log ${i} exceeds the depth-${depth} tree capacity of ${capacity} leaves`,
        );
      }
      const root = await tree.insert(log.leaf);
      if (!root.equals(log.newRoot)) {
        throw new LeafHistoryError(
          "ROOT_MISMATCH",
          `LeafInserted log ${i}: recomputed root ${root.toString()} != logged newRoot ${log.newRoot.toString()}`,
        );
      }
      rootBySize.push(root);
      sizeByRoot.set(root.toBigInt(), i + 1);
    }
    return new LeafHistory(tree, rootBySize, sizeByRoot);
  }

  /** Number of leaves seen, i.e. the current size. */
  get size(): number {
    return this.rootBySize.length;
  }

  /** The tree size at which `root` was the current root, or undefined if this pool never had it. */
  sizeAt(root: Fr): number | undefined {
    return this.sizeByRoot.get(root.toBigInt());
  }

  /** The size `root` maps to, refusing an unknown root or a taker's hint that disagrees with the logs. */
  resolveSize(root: Fr, hintedSize: number): number {
    const size = this.sizeAt(root);
    if (size === undefined) {
      throw new LeafHistoryError(
        "UNKNOWN_ROOT",
        `root ${root.toString()} is not a root of this pool's tree (${this.size} leaves indexed)`,
      );
    }
    if (size !== hintedSize) {
      throw new LeafHistoryError(
        "SIZE_HINT_MISMATCH",
        `root ${root.toString()} is the root at size ${size}, but the hint says ${hintedSize}`,
      );
    }
    return size;
  }

  /** The root of the tree holding exactly the first `size` leaves. */
  rootAt(size: number): Fr {
    this.assertSize(size);
    return this.rootBySize[size - 1]!;
  }

  /**
   * The inclusion path of `leafIndex` in the tree of exactly `size` leaves, verified to fold (with the circuit's
   * level-absorbing hash) to the logged root at that size before it is returned.
   */
  async pathAt(
    leafIndex: number,
    size: number,
  ): Promise<{ siblings: Fr[]; root: Fr }> {
    this.assertSize(size);
    if (!Number.isSafeInteger(leafIndex) || leafIndex < 0) {
      throw new LeafHistoryError(
        "INDEX_NOT_BELOW_SIZE",
        `leaf index ${leafIndex} is not a non-negative integer`,
      );
    }
    if (leafIndex >= size) {
      throw new LeafHistoryError(
        "INDEX_NOT_BELOW_SIZE",
        `leaf index ${leafIndex} is not inside the tree of size ${size}; a note inserted after the root cannot be proven against it`,
      );
    }
    const siblings: Fr[] = [];
    let index = leafIndex;
    for (let level = 0; level < this.tree.depth; level++) {
      siblings.push(
        await this.nodeAt(level, index % 2 === 0 ? index + 1 : index - 1, size),
      );
      index = Math.floor(index / 2);
    }
    const root = this.rootAt(size);
    const folded = await foldPath(
      this.tree.levels[0]![leafIndex]!,
      leafIndex,
      siblings,
    );
    if (!folded.equals(root)) {
      throw new LeafHistoryError(
        "ROOT_MISMATCH",
        `path for leaf ${leafIndex} at size ${size} folds to ${folded.toString()}, not the logged root ${root.toString()}`,
      );
    }
    return { siblings, root };
  }

  private assertSize(size: number): void {
    if (!Number.isSafeInteger(size) || size < 1 || size > this.size) {
      throw new LeafHistoryError(
        "SIZE_OUT_OF_RANGE",
        `tree size ${size} is outside 1..${this.size} (the sizes this history has seen)`,
      );
    }
  }

  /**
   * Node `index` at `level` in the tree of the first `size` leaves. A subtree that was already full at `size`
   * never changes afterwards, so it is read from the current tree; only the one partial subtree per level is
   * recombined, which keeps a path at O(depth^2) hashes instead of a rebuild of `size` leaves.
   */
  private async nodeAt(
    level: number,
    index: number,
    size: number,
  ): Promise<Fr> {
    const width = 2 ** level;
    const start = index * width;
    if (start >= size) return ZERO;
    if (level === 0) return this.tree.levels[0]![index]!;
    if (start + width <= size && level < this.tree.depth) {
      return this.tree.levels[level]![index]!;
    }
    const left = await this.nodeAt(level - 1, 2 * index, size);
    const right = await this.nodeAt(level - 1, 2 * index + 1, size);
    // The lean rule of LeanIMT.insert and MerkleTreeLib: an empty right child passes the left child up unhashed.
    if (right.equals(ZERO)) return left;
    return Poseidon.hash([left, right, toFr(BigInt(level - 1))]);
  }
}
