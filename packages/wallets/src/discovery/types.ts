import { Fr } from "@aztec/foundation/fields";

// The contract Howl asks of a private-discovery service (Raven). Downloading every event and filtering
// locally satisfies these types but defeats their purpose, so an implementation is judged on query shape
// as much as on correctness.

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

/** `occurrenceCount` is server-chosen and becomes a batch size, so unbounded it wedges the device. */
export const MAX_OCCURRENCES_PER_TAG = 100_000;

/** DB2 block size, 2^k leaves. k=10 gives a 1-in-1024 anonymity set for a plain, non-PIR fetch. */
export const LEAF_BLOCK_LOG2 = 10;
export const LEAF_BLOCK_SIZE = 1 << LEAF_BLOCK_LOG2;

/** One row of DB1, decoded. `ephemeralPkX` and `cekWrap` are zero on a self row. */
export interface HowlNoteRecord {
  readonly layoutVersion: number;
  readonly recordKind: RecordKind;
  readonly leafIndex: number;
  /** commitment[0..16]. A probe returns a row on a MISS too, so this is how a false hit is rejected. */
  readonly commitmentPrefix: Uint8Array;
  readonly ephemeralPkX: Fr;
  readonly cekWrap: Fr;
  /** The 5 surviving ciphertext words, in CIPHERTEXT_KEPT_INDICES order. */
  readonly ciphertextKept: readonly Fr[];
}

// A tag identifies an ADDRESS, not a note. Returning the count with the first row is what caps a cold
// restore of arbitrary history at two round trips instead of one per note.
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

  /** DB2. Deliberately NOT private: the client already knows its leafIndex. Never build this on PIR. */
  fetchLeafBlock(blockIndex: number): Promise<readonly Fr[]>;
}
