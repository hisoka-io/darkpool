import { Fr } from "@aztec/foundation/fields";

/**
 * The contract Howl asks of a private-discovery service (Raven).
 *
 * Howl's differentiator over trial-decrypt pools is that a wallet computes its own discovery tag locally
 * and fetches only its own rows, in a bounded number of round trips that does not grow with pool size.
 * Downloading every event and filtering locally satisfies the types here but defeats the purpose, so an
 * implementation is judged on query shape as much as on correctness.
 */

/** DB1 serves both note families from one table; the kind selects which fields carry data. */
export const RECORD_KIND_SELF = 0;
export const RECORD_KIND_INCOMING = 1;
export type RecordKind = typeof RECORD_KIND_SELF | typeof RECORD_KIND_INCOMING;

/** Wire constants, fixed by the DB1 cell law: 246 bytes of payload inside a 256-byte cell. */
export const HOWL_NOTE_LAYOUT_VERSION = 1;
export const HOWL_NOTE_RECORD_BYTES = 246;
export const HOWL_NOTE_CELL_BYTES = 256;
export const COMMITMENT_PREFIX_BYTES = 16;
/** Ciphertext words the server keeps. Words 0 (note_version) and 5 (owner) are stripped; see reconstruct. */
export const CIPHERTEXT_KEPT_INDICES = [1, 2, 3, 4, 6] as const;

/**
 * Ceiling on how many rows one tag may claim in round 2.
 *
 * `occurrenceCount` is a server-chosen integer that the client turns directly into a batch size. Unbounded,
 * one hostile or corrupt response allocates an arbitrarily large array on every sync, which wedges the
 * device on a boot loop rather than merely failing a request. The cap is far above any legitimate receiving
 * address: a real one accumulates payments, not hundreds of thousands of them.
 */
export const MAX_OCCURRENCES_PER_TAG = 100_000;

/** DB2 block size, 2^k leaves. k=10 gives a 1-in-1024 anonymity set for a plain, non-PIR fetch. */
export const LEAF_BLOCK_LOG2 = 10;
export const LEAF_BLOCK_SIZE = 1 << LEAF_BLOCK_LOG2;

/** One row of DB1, decoded. `ephemeralPkX` and `cekWrap` are zero on a self row. */
export interface HowlNoteRecord {
  readonly layoutVersion: number;
  readonly recordKind: RecordKind;
  readonly leafIndex: number;
  /**
   * commitment[0..16]. A cuckoo probe returns a row on a MISS as well as a hit, so the client rejects a
   * false hit locally by comparing this against the commitment it recomputes from the decrypted note.
   */
  readonly commitmentPrefix: Uint8Array;
  readonly ephemeralPkX: Fr;
  readonly cekWrap: Fr;
  /** The 5 surviving ciphertext words, in CIPHERTEXT_KEPT_INDICES order. */
  readonly ciphertextKept: readonly Fr[];
}

/**
 * Round-1 result for one tag.
 *
 * A tag identifies an ADDRESS, not a note, so a long-lived receiving address accumulates many notes under
 * one tag. Round 1 returns the first note plus the total, which is what lets a cold restore of arbitrary
 * history complete in two round trips instead of one per note.
 */
export interface FirstOccurrence {
  readonly tag: Fr;
  /** Null when the tag has no notes. A probe miss decodes to a record that fails the prefix check. */
  readonly record: HowlNoteRecord | null;
  readonly occurrenceCount: number;
}

export interface OccurrenceRequest {
  readonly tag: Fr;
  /** 1-based here: occurrence 0 already came back from round 1. */
  readonly occurrence: number;
}

export interface DiscoverySource {
  /** Round 1. One padded batch over every candidate tag. */
  probeFirst(tags: readonly Fr[]): Promise<readonly FirstOccurrence[]>;

  /** Round 2. Every remaining occurrence, independent, one padded batch. */
  fetchOccurrences(
    requests: readonly OccurrenceRequest[],
  ): Promise<readonly (HowlNoteRecord | null)[]>;

  /**
   * DB2. A plain indexed fetch and deliberately NOT private: by this point the client already knows its
   * leafIndex, and the block reveals only which 2^k-leaf bucket it wants. Never build this on the PIR path.
   */
  fetchLeafBlock(blockIndex: number): Promise<readonly Fr[]>;
}
