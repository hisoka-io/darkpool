import type { Fr } from "@aztec/foundation/fields";

/** The verified tree leaf at a position, or `"unheld"` when the adapter cannot answer without a request. */
export interface VerifiedLeafSource {
  leafAt(leafIndex: number): Promise<Fr | "unheld">;
}

export interface TreeWitness {
  readonly leafIndex: number;
  readonly leafCount: number;
  readonly leaf: Fr;
  readonly siblings: readonly Fr[];
  readonly root: Fr;
}

/**
 * Merkle paths keyed by index and tree size. Both production sources (a local tree, Raven blocks) compute the
 * path on the device, so the index never leaves it except through a plain block read, and the explicit size
 * lets a join take both paths in one tree. Answers are untrusted: every one is folded and checked.
 */
export interface WitnessPort {
  /** Path of `leafIndex` in the tree of the first `leafCount` leaves. */
  witness(leafIndex: number, leafCount: number): Promise<TreeWitness>;
}
