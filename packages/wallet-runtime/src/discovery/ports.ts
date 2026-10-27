import type { Fr } from "@aztec/foundation/fields";
import type { HowlNoteRecord } from "@hisoka/wallets";
import type { BlockId, BlockRef } from "../chain/rpc.js";

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

export interface DiscoveryHead {
  readonly leafCount: number;
  readonly root: Fr;
  readonly block: BlockRef;
  /** Set when the adapter dropped state at or past this leaf index (a reorg). */
  readonly rewoundTo?: number;
  /** The newest block the adapter kept across that reorg, when it knows one. */
  readonly ancestor?: BlockId;
}

export interface TagMatches {
  readonly tag: Fr;
  /** Every matching leaf index, ascending, never 0 (the genesis leaf). */
  readonly positions: readonly number[];
  /** One per position, same order. */
  readonly records: readonly HowlNoteRecord[];
  /**
   * Inclusion block per position when the adapter knows it (self-index reads it from the log), else null and
   * the runtime files the note under the sync head.
   */
  readonly blocks: readonly (BlockId | null)[];
}

/**
 * The production discovery contract (self-index or Raven).
 *
 * `match` and `leafAt` answer against the head of the last `sync()`, which reaches `latest`, unconfirmed
 * blocks included: ephemeral-index occupancy must see notes that are not yet confirmed.
 */
export interface DiscoveryPort {
  sync(): Promise<DiscoveryHead>;
  /** One entry per requested tag, in request order, with EVERY matched position. */
  match(tags: readonly Fr[]): Promise<readonly TagMatches[]>;
  leafAt(leafIndex: number): Promise<Fr | "unheld">;
}
