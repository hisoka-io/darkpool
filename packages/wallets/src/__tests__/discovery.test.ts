import { describe, expect, it } from "vitest";
import { Fr } from "@aztec/foundation/fields";
import { demEncrypt, demDecrypt, DEM_FIELDS } from "../crypto/dem.js";
import { NOTE_VERSION } from "../note/note.js";
import {
  CIPHERTEXT_KEPT_INDICES,
  COMMITMENT_PREFIX_BYTES,
  HOWL_NOTE_CELL_BYTES,
  HOWL_NOTE_LAYOUT_VERSION,
  RECORD_KIND_INCOMING,
  RECORD_KIND_SELF,
  type HowlNoteRecord,
} from "../discovery/types.js";
import {
  commitmentPrefixMatches,
  decodeHowlNoteRecord,
  encodeHowlNoteRecord,
} from "../discovery/codec.js";
import { reconstructCiphertext } from "../discovery/reconstruct.js";

const CEK = new Fr(0x2f1c9a4bd77e3051n);
const OWNER = new Fr(0x1234567890abcdefn);

function plaintext(): Fr[] {
  // [note_version, asset_id, note_type, conditions_hash, value, owner, parents]
  return [
    NOTE_VERSION,
    new Fr(0xaan),
    new Fr(0n),
    new Fr(0n),
    new Fr(1_000n),
    OWNER,
    new Fr(0n),
  ];
}

async function strippedRecord(
  kind: typeof RECORD_KIND_SELF | typeof RECORD_KIND_INCOMING,
  commitment: Fr,
): Promise<HowlNoteRecord> {
  const ct = await demEncrypt(CEK, plaintext());
  return {
    layoutVersion: HOWL_NOTE_LAYOUT_VERSION,
    recordKind: kind,
    leafIndex: 918_273,
    commitmentPrefix: commitment
      .toBuffer()
      .subarray(0, COMMITMENT_PREFIX_BYTES),
    ephemeralPkX: kind === RECORD_KIND_SELF ? Fr.ZERO : new Fr(0xeeen),
    cekWrap: kind === RECORD_KIND_SELF ? Fr.ZERO : new Fr(0xfffn),
    ciphertextKept: CIPHERTEXT_KEPT_INDICES.map((i) => ct[i]),
  };
}

describe("howl-note-v1 discovery record", () => {
  it("round-trips encrypt, strip, reconstruct, decrypt back to the original note", async () => {
    const record = await strippedRecord(RECORD_KIND_SELF, new Fr(7n));
    const rebuilt = await reconstructCiphertext(record, CEK, OWNER);

    expect(rebuilt).toHaveLength(DEM_FIELDS);
    const decrypted = await demDecrypt(CEK, rebuilt);
    expect(decrypted.map((f) => f.toString())).toEqual(
      plaintext().map((f) => f.toString()),
    );
  });

  it("reconstructs the two stripped words rather than carrying them", async () => {
    const record = await strippedRecord(RECORD_KIND_SELF, new Fr(7n));
    // 7 transmitted words, 5 on the wire: the saving IS the strip.
    expect(record.ciphertextKept).toHaveLength(5);
    expect(CIPHERTEXT_KEPT_INDICES).toEqual([1, 2, 3, 4, 6]);

    const full = await reconstructCiphertext(record, CEK, OWNER);
    const truth = await demEncrypt(CEK, plaintext());
    expect(full[0].toString()).toBe(truth[0].toString());
    expect(full[5].toString()).toBe(truth[5].toString());
  });

  it("fails to recover the note when the owner commitment is wrong", async () => {
    const record = await strippedRecord(RECORD_KIND_SELF, new Fr(7n));
    const rebuilt = await reconstructCiphertext(record, CEK, new Fr(0xdeadn));
    const decrypted = await demDecrypt(CEK, rebuilt);
    // Every other field survives; only the reconstructed word is wrong, which is what the leaf check catches.
    expect(decrypted[5].toString()).not.toBe(OWNER.toString());
    expect(decrypted[4].toString()).toBe(new Fr(1_000n).toString());
  });

  it("encodes to exactly one 256-byte cell and decodes back identically", async () => {
    const record = await strippedRecord(RECORD_KIND_INCOMING, new Fr(0x99n));
    const cell = encodeHowlNoteRecord(record);
    expect(cell).toHaveLength(HOWL_NOTE_CELL_BYTES);

    const back = decodeHowlNoteRecord(cell);
    expect(back.recordKind).toBe(RECORD_KIND_INCOMING);
    expect(back.leafIndex).toBe(918_273);
    expect(back.ephemeralPkX.toString()).toBe(record.ephemeralPkX.toString());
    expect(back.cekWrap.toString()).toBe(record.cekWrap.toString());
    expect(back.ciphertextKept.map((f) => f.toString())).toEqual(
      record.ciphertextKept.map((f) => f.toString()),
    );
  });

  it("zero-fills eph and cekWrap on a self row", async () => {
    const record = await strippedRecord(RECORD_KIND_SELF, new Fr(7n));
    const back = decodeHowlNoteRecord(encodeHowlNoteRecord(record));
    expect(back.ephemeralPkX.isZero()).toBe(true);
    expect(back.cekWrap.isZero()).toBe(true);
  });

  // Realistic commitments only: the prefix is the TOP 16 bytes big-endian, so any small field element
  // prefixes to all zeros and every small value would appear to match every other.
  it("rejects a probe miss via the commitment prefix", async () => {
    const commitment = new Fr(
      0x1b0d907a380f17256cbc6532a0410ce06677b19f25c21b15bc15bf179133b4edn,
    );
    const other = new Fr(
      0x2c4f81ab99e0233d7ae1450bb8cc2119f0aa77e3d4661cc9022f88a7135dd001n,
    );
    const record = await strippedRecord(RECORD_KIND_SELF, commitment);
    expect(commitmentPrefixMatches(record, commitment)).toBe(true);
    expect(commitmentPrefixMatches(record, other)).toBe(false);
  });

  it("cannot distinguish two commitments that share a 16-byte prefix, which is why the leaf check is final", async () => {
    const a = new Fr(
      0x1b0d907a380f17256cbc6532a0410ce000000000000000000000000000000001n,
    );
    const b = new Fr(
      0x1b0d907a380f17256cbc6532a0410ce000000000000000000000000000000002n,
    );
    const record = await strippedRecord(RECORD_KIND_SELF, a);
    expect(commitmentPrefixMatches(record, b)).toBe(true);
  });

  it("refuses a cell whose padding is not zero", async () => {
    const record = await strippedRecord(RECORD_KIND_SELF, new Fr(7n));
    const cell = encodeHowlNoteRecord(record);
    cell[250] = 1;
    expect(() => decodeHowlNoteRecord(cell)).toThrow(/padding is non-zero/);
  });

  it("refuses an unknown layout version rather than misreading the fields", async () => {
    const record = await strippedRecord(RECORD_KIND_SELF, new Fr(7n));
    const cell = encodeHowlNoteRecord(record);
    cell[0] = 2;
    expect(() => decodeHowlNoteRecord(cell)).toThrow(/layout version 2/);
  });
});
