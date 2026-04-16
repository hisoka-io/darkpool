import { describe, it, expect, beforeAll } from "vitest";
import { Fr } from "@aztec/foundation/fields";
import { toFr } from "../crypto/fields";
import {
  aes128Encrypt,
  aes128Decrypt,
  encryptNoteDeposit,
  decryptNoteDeposit,
  packNotePlaintext,
  unpackNotePlaintext,
  NotePlaintext,
} from "../crypto";
import { Kdf } from "../crypto/Kdf";
import { Base8, mulPointEscalar, Point } from "@zk-kit/baby-jubjub";

const COMPLIANCE_SK = 987654321n;
const COMPLIANCE_PK: Point<bigint> = mulPointEscalar(Base8, COMPLIANCE_SK);

describe("Encryption (Unified Note)", () => {
  let sk_view: Fr;
  let nonce: Fr;
  let note_plain: NotePlaintext;
  let plaintext_192: Buffer;

  beforeAll(() => {
    sk_view = toFr(12345n);
    nonce = toFr(1n);
    note_plain = {
      asset_id: toFr(123n),
      value: toFr(100n),
      secret: toFr(456n),
      nullifier: toFr(789n),
      timelock: toFr(0n), // New field
      hashlock: toFr(0n), // New field
    };
    plaintext_192 = packNotePlaintext(note_plain);
  });

  describe("Core Primitives", () => {
    it("aes128Encrypt pads 192b to 208b", async () => {
      const dummy_key = Buffer.alloc(16, 0x01);
      const dummy_iv = Buffer.alloc(16, 0x02);
      const ct = await aes128Encrypt(plaintext_192, dummy_key, dummy_iv);
      // 192 bytes = 12 blocks. PKCS7 adds a full block of padding (16 bytes).
      // Total = 192 + 16 = 208.
      expect(ct.length).toBe(208);
    });

    it("aes128Decrypt strips pad to 192b", async () => {
      const dummy_key = Buffer.alloc(16, 0x01);
      const dummy_iv = Buffer.alloc(16, 0x02);
      const ct = await aes128Encrypt(plaintext_192, dummy_key, dummy_iv);
      const plain = await aes128Decrypt(ct, dummy_key, dummy_iv);
      expect(plain.length).toBe(192);
      expect(plain.equals(plaintext_192)).toBe(true);
    });
  });

  describe("Pack/Unpack", () => {
    it("packs 6 Fr to 192b BE Buffer", () => {
      const packed = packNotePlaintext(note_plain);
      expect(packed.length).toBe(192);
      expect(packed.slice(0, 32).equals(note_plain.asset_id.toBuffer())).toBe(
        true,
      );
      // Hashlock is the last field
      expect(
        packed.slice(160, 192).equals(note_plain.hashlock.toBuffer()),
      ).toBe(true);
    });

    it("unpacks 192b to NotePlaintext", () => {
      const packed = packNotePlaintext(note_plain);
      const unpacked = unpackNotePlaintext(packed);
      expect(unpacked.asset_id.equals(note_plain.asset_id)).toBe(true);
      expect(unpacked.timelock.equals(note_plain.timelock)).toBe(true);
    });
  });

  describe("Deposit Encryption", () => {
    it("encryptNoteDeposit produces 208b ct", async () => {
      const { ciphertext, value_out } = await encryptNoteDeposit(
        sk_view,
        nonce,
        note_plain,
        COMPLIANCE_PK,
      );
      expect(ciphertext.length).toBe(208);
      expect(value_out.equals(note_plain.value)).toBe(true);
    });

    it("decryptNoteDeposit roundtrips", async () => {
      const enc = await encryptNoteDeposit(
        sk_view,
        nonce,
        note_plain,
        COMPLIANCE_PK,
      );
      const ephemeral_sk = await Kdf.derive("hisoka.ephemeral", sk_view, nonce);
      const decrypted = await decryptNoteDeposit(
        ephemeral_sk,
        COMPLIANCE_PK,
        enc.ciphertext,
      );
      expect(decrypted.asset_id.equals(note_plain.asset_id)).toBe(true);
      expect(decrypted.timelock.equals(note_plain.timelock)).toBe(true);
    });
  });
});
