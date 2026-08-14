import { Fr } from "@aztec/foundation/fields";
import {
  COMMITMENT_PREFIX_BYTES,
  CIPHERTEXT_KEPT_INDICES,
  HOWL_NOTE_CELL_BYTES,
  HOWL_NOTE_LAYOUT_VERSION,
  HOWL_NOTE_RECORD_BYTES,
  HowlNoteRecord,
  RECORD_KIND_INCOMING,
  RECORD_KIND_SELF,
  RecordKind,
} from "./types.js";

// Field offsets are wire-frozen: an implementation on the other side of the network decodes by these.
const OFF_LAYOUT = 0;
const OFF_KIND = 1;
const OFF_LEAF_INDEX = 2;
const OFF_COMMITMENT_PREFIX = 6;
const OFF_EPH_X = 22;
const OFF_CEK_WRAP = 54;
const OFF_CIPHERTEXT = 86;
const FIELD_BYTES = 32;

function putField(out: Uint8Array, offset: number, value: Fr): void {
  const bytes = value.toBuffer();
  if (bytes.length !== FIELD_BYTES) {
    throw new Error(
      `field serialises to ${bytes.length} bytes, expected ${FIELD_BYTES}`,
    );
  }
  out.set(bytes, offset);
}

function readField(src: Uint8Array, offset: number): Fr {
  return Fr.fromBuffer(Buffer.from(src.subarray(offset, offset + FIELD_BYTES)));
}

/** Encodes to the full 256-byte cell; the trailing 10 bytes are zero padding, not payload. */
export function encodeHowlNoteRecord(record: HowlNoteRecord): Uint8Array {
  if (record.ciphertextKept.length !== CIPHERTEXT_KEPT_INDICES.length) {
    throw new Error(
      `record carries ${record.ciphertextKept.length} kept ciphertext words, expected ${CIPHERTEXT_KEPT_INDICES.length}`,
    );
  }
  if (record.commitmentPrefix.length !== COMMITMENT_PREFIX_BYTES) {
    throw new Error(
      `commitment prefix is ${record.commitmentPrefix.length} bytes, expected ${COMMITMENT_PREFIX_BYTES}`,
    );
  }
  if (
    !Number.isInteger(record.leafIndex) ||
    record.leafIndex < 0 ||
    record.leafIndex > 0xffffffff
  ) {
    throw new Error(`leafIndex ${record.leafIndex} is not a u32`);
  }

  const out = new Uint8Array(HOWL_NOTE_CELL_BYTES);
  out[OFF_LAYOUT] = record.layoutVersion;
  out[OFF_KIND] = record.recordKind;
  new DataView(out.buffer).setUint32(OFF_LEAF_INDEX, record.leafIndex, false);
  out.set(record.commitmentPrefix, OFF_COMMITMENT_PREFIX);
  putField(out, OFF_EPH_X, record.ephemeralPkX);
  putField(out, OFF_CEK_WRAP, record.cekWrap);
  record.ciphertextKept.forEach((word, i) => {
    putField(out, OFF_CIPHERTEXT + i * FIELD_BYTES, word);
  });
  return out;
}

export function decodeHowlNoteRecord(cell: Uint8Array): HowlNoteRecord {
  if (cell.length !== HOWL_NOTE_CELL_BYTES) {
    throw new Error(
      `cell is ${cell.length} bytes, expected ${HOWL_NOTE_CELL_BYTES}`,
    );
  }
  const layoutVersion = cell[OFF_LAYOUT];
  if (layoutVersion !== HOWL_NOTE_LAYOUT_VERSION) {
    throw new Error(
      `record layout version ${layoutVersion} is not the supported ${HOWL_NOTE_LAYOUT_VERSION}`,
    );
  }
  const kind = cell[OFF_KIND];
  if (kind !== RECORD_KIND_SELF && kind !== RECORD_KIND_INCOMING) {
    throw new Error(`record kind ${kind} is neither self nor incoming`);
  }
  // Padding is part of the contract: a non-zero tail means the sender used a layout this build cannot read.
  for (let i = HOWL_NOTE_RECORD_BYTES; i < HOWL_NOTE_CELL_BYTES; i++) {
    if (cell[i] !== 0) throw new Error(`cell padding is non-zero at byte ${i}`);
  }

  return {
    layoutVersion,
    recordKind: kind as RecordKind,
    leafIndex: new DataView(
      cell.buffer,
      cell.byteOffset,
      cell.byteLength,
    ).getUint32(OFF_LEAF_INDEX, false),
    commitmentPrefix: cell.slice(
      OFF_COMMITMENT_PREFIX,
      OFF_COMMITMENT_PREFIX + COMMITMENT_PREFIX_BYTES,
    ),
    ephemeralPkX: readField(cell, OFF_EPH_X),
    cekWrap: readField(cell, OFF_CEK_WRAP),
    ciphertextKept: CIPHERTEXT_KEPT_INDICES.map((_, i) =>
      readField(cell, OFF_CIPHERTEXT + i * FIELD_BYTES),
    ),
  };
}

/** True when this row plausibly belongs to the commitment the client recomputed. Rejects a probe miss. */
export function commitmentPrefixMatches(
  record: HowlNoteRecord,
  commitment: Fr,
): boolean {
  const expected = commitment.toBuffer().subarray(0, COMMITMENT_PREFIX_BYTES);
  return record.commitmentPrefix.every((b, i) => b === expected[i]);
}
