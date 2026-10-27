import { Fr } from "@aztec/foundation/fields";
import {
  CIPHERTEXT_KEPT_INDICES,
  COMMITMENT_PREFIX_BYTES,
  HOWL_NOTE_LAYOUT_VERSION,
  RECORD_KIND_INCOMING,
  RECORD_KIND_SELF,
  type HowlNoteRecord,
} from "@hisoka/wallets";

/** Ciphertext words a note event carries; a change here is an ABI change. */
export const PACKED_CIPHERTEXT_WORDS = 7;

export interface NewNoteEvent {
  readonly kind: "NEW_NOTE";
  readonly leafIndex: number;
  readonly commitment: Fr;
  readonly ephemeralX: Fr;
  readonly packedCiphertext: readonly Fr[];
}

export interface NewPrivateMemoEvent {
  readonly kind: "NEW_MEMO";
  readonly leafIndex: number;
  readonly commitment: Fr;
  readonly tag: Fr;
  readonly ephemeralX: Fr;
  readonly cekWrap: Fr;
  readonly packedCiphertext: readonly Fr[];
}

export type ChainNoteEvent = NewNoteEvent | NewPrivateMemoEvent;

/**
 * Drops ciphertext words 0 (`note_version`) and 5 (`owner`), which every recipient rebuilds, so a self-index
 * row is byte-for-byte the row a Raven cell carries and one opener serves both.
 */
function strip(
  event: ChainNoteEvent,
): Pick<HowlNoteRecord, "ciphertextKept" | "commitmentPrefix"> {
  if (event.packedCiphertext.length !== PACKED_CIPHERTEXT_WORDS) {
    throw new Error(
      `packedCiphertext has ${event.packedCiphertext.length} words, expected ${PACKED_CIPHERTEXT_WORDS}`,
    );
  }
  return {
    ciphertextKept: CIPHERTEXT_KEPT_INDICES.map(
      (i: number) => event.packedCiphertext[i] ?? Fr.ZERO,
    ),
    commitmentPrefix: event.commitment
      .toBuffer()
      .subarray(0, COMMITMENT_PREFIX_BYTES),
  };
}

/**
 * The tag a row is filed under: a self note under its ephemeral's public x, an incoming note under the
 * recipient's view key. A note minted with an ephemeral its owner cannot re-derive lands under a tag no
 * scanner computes.
 */
export function tagOf(event: ChainNoteEvent): Fr {
  return event.kind === "NEW_NOTE" ? event.ephemeralX : event.tag;
}

export function toRecord(event: ChainNoteEvent): HowlNoteRecord {
  const { ciphertextKept, commitmentPrefix } = strip(event);
  const common = {
    layoutVersion: HOWL_NOTE_LAYOUT_VERSION,
    leafIndex: event.leafIndex,
    commitmentPrefix,
    ciphertextKept,
  };
  return event.kind === "NEW_NOTE"
    ? {
        ...common,
        recordKind: RECORD_KIND_SELF,
        ephemeralPkX: Fr.ZERO,
        cekWrap: Fr.ZERO,
      }
    : {
        ...common,
        recordKind: RECORD_KIND_INCOMING,
        ephemeralPkX: event.ephemeralX,
        cekWrap: event.cekWrap,
      };
}
