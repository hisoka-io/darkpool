import { Fr } from "@aztec/foundation/fields";
import {
  COMMITMENT_PREFIX_BYTES,
  CIPHERTEXT_KEPT_INDICES,
  HOWL_NOTE_LAYOUT_VERSION,
  RECORD_KIND_INCOMING,
  RECORD_KIND_SELF,
  type HowlNoteRecord,
} from "@hisoka/wallets";
import { MockRaven } from "./mockRaven.js";

/**
 * Stands in for Raven's chain indexer: turns the two note events into DB1 rows and DB2 leaves.
 *
 * It performs the STRIP, which is the whole reason the record is 246 bytes and not 310: ciphertext words 0
 * and 5 never leave the chain, because the client reconstructs both. Everything strip-aware on the client
 * side lives in `reconstructCiphertext`, so this is the only other place that knows about it.
 */

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

function strip(
  event: ChainNoteEvent,
): Pick<HowlNoteRecord, "ciphertextKept" | "commitmentPrefix"> {
  if (event.packedCiphertext.length !== 7) {
    // One line, and it is the entire tripwire for a DEM_FIELDS change, which is an ABI change.
    throw new Error(
      `packedCiphertext has ${event.packedCiphertext.length} words, expected 7`,
    );
  }
  return {
    ciphertextKept: CIPHERTEXT_KEPT_INDICES.map(
      (i: number) => event.packedCiphertext[i],
    ),
    commitmentPrefix: event.commitment
      .toBuffer()
      .subarray(0, COMMITMENT_PREFIX_BYTES),
  };
}

/**
 * The tag a row is filed under, which is the ONLY thing a client can address a note by.
 *
 * Self notes are filed under the ephemeral's own public x; incoming notes under the recipient's view key.
 * A note minted with an ephemeral the owner cannot re-derive therefore lands under a tag no scanner will
 * ever compute, which is precisely how a note becomes invisible to its owner.
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

/** Feeds a stream of chain events into DB1 and DB2, in the order the chain emitted them. */
export function indexEvents(
  raven: MockRaven,
  events: readonly ChainNoteEvent[],
): void {
  for (const event of events) {
    raven.insert(tagOf(event), toRecord(event));
    raven.appendLeaf(event.commitment);
  }
}
