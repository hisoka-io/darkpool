import { describe, it, expect } from "vitest";
import { Fr } from "@aztec/foundation/fields";
import { Base8, mulPointEscalar, Point } from "@zk-kit/baby-jubjub";
import { Note } from "../utxo/Note";
import {
  NotePlaintext,
  deriveSharedSecret,
  kdfToAesKeyIV,
  aes128Encrypt,
  packNotePlaintext,
  unpackCiphertext,
} from "../crypto";
import { Poseidon } from "../crypto/Poseidon";
import { toFr, addressToFr } from "../crypto/fields";
import { DarkAccount } from "../keys/DarkAccount";
import { KeyRepository } from "../state/KeyRepository";
import { NoteProcessor } from "../sync/NoteProcessor";
import { UnprocessedEvent } from "../sync/types";

const MNEMONIC = "test test test test test test test test test test test junk";
const COMPLIANCE_PK: Point<bigint> = mulPointEscalar(Base8, 987654321n);

function packCiphertext(ct: Buffer): Fr[] {
  const packed: Fr[] = [];
  let idx = 0;
  for (let p = 0; p < 7; p++) {
    const bytesInThis = p < 6 ? 31 : 22;
    let val = 0n;
    let power = 1n;
    for (let i = 0; i < bytesInThis; i++) {
      val += BigInt(ct[idx]!) * power;
      power *= 256n;
      idx++;
    }
    packed.push(new Fr(val));
  }
  return packed;
}

describe("Note (Unified)", () => {
  const samplePlaintext: NotePlaintext = {
    asset_id: addressToFr("0x0d500B1d8E8eF31E21C99d1Db9A6444d3ADf1270"),
    value: toFr(100n * 10n ** 18n),
    secret: new Fr(12345n),
    nullifier: new Fr(67890n),
    timelock: toFr(0n),
    hashlock: toFr(0n),
  };

  const note = new Note(samplePlaintext);

  it("derives the Path-A nullifier as Poseidon(nullifier, commitment, leafIndex)", async () => {
    const commitment = new Fr(0x1234abcdn);
    const leafIndex = 5;

    const hash1 = await note.getNullifierHash(commitment, leafIndex);
    const hash2 = await note.getNullifierHash(commitment, leafIndex);
    expect(hash1).toBeInstanceOf(Fr);
    expect(hash1.equals(hash2)).toBe(true);

    const expected = await Poseidon.hash([
      samplePlaintext.nullifier,
      commitment,
      new Fr(BigInt(leafIndex)),
    ]);
    expect(hash1.equals(expected)).toBe(true);
  });

  it("binds the nullifier to the leaf position", async () => {
    const commitment = new Fr(0x1234abcdn);
    const atIndex5 = await note.getNullifierHash(commitment, 5);
    const atIndex6 = await note.getNullifierHash(commitment, 6);
    expect(atIndex5.equals(atIndex6)).toBe(false);
  });

  it("should throw an error for a negative value", () => {
    const invalidPlaintext = { ...samplePlaintext, value: toFr(1n) };
    invalidPlaintext.value.toBigInt = () => -1n;
    expect(() => new Note(invalidPlaintext)).toThrow(
      "Note value cannot be negative.",
    );
  });

  it("should throw for a self-owned note with a zero nullifier", () => {
    const zeroNullifier = { ...samplePlaintext, nullifier: new Fr(0n) };
    expect(() => new Note(zeroNullifier)).toThrow(
      "Self-owned note nullifier must be non-zero",
    );
  });
});

describe("Path-A deposit scan stores the ECDH shared secret (S-1)", () => {
  it("scanned spendingSecret is the prover oldSharedSecret and recomputes the leaf commitment", async () => {
    const account = await DarkAccount.fromMnemonic(MNEMONIC);
    const keyRepo = new KeyRepository(account, COMPLIANCE_PK);
    await keyRepo.ensureEphemeralLookahead(2);

    const index = 0n;
    const esk = await account.getEphemeralOutgoingKey(index);
    const epk = await account.getPublicEphemeralOutgoingKey(index);
    const sharedSecret = await deriveSharedSecret(esk, COMPLIANCE_PK);

    const note: NotePlaintext = {
      asset_id: addressToFr("0x0d500B1d8E8eF31E21C99d1Db9A6444d3ADf1270"),
      value: toFr(100n),
      secret: new Fr(12345n),
      nullifier: new Fr(67890n),
      timelock: toFr(0n),
      hashlock: toFr(0n),
    };

    const { key, iv } = await kdfToAesKeyIV(sharedSecret);
    const ciphertext = await aes128Encrypt(packNotePlaintext(note), key, iv);
    const packed = packCiphertext(ciphertext);
    expect(unpackCiphertext(packed).equals(ciphertext)).toBe(true);
    const commitment = await Poseidon.hash(packed);

    const event: UnprocessedEvent = {
      type: "NEW_NOTE",
      blockNumber: 1,
      txHash: "0x00",
      args: {
        leafIndex: 0n,
        commitment: "0x" + commitment.toBigInt().toString(16),
        epkX: epk[0],
        epkY: epk[1],
        packedCiphertext: packed.map((f) => "0x" + f.toBigInt().toString(16)),
      },
    };

    const processor = new NoteProcessor(keyRepo, COMPLIANCE_PK);
    const walletNote = await processor.process(event);
    expect(walletNote).not.toBeNull();

    expect(walletNote!.spendingSecret.equals(sharedSecret)).toBe(true);
    expect(walletNote!.spendingSecret.equals(esk)).toBe(false);

    const r = await kdfToAesKeyIV(walletNote!.spendingSecret);
    const ct2 = await aes128Encrypt(
      packNotePlaintext(walletNote!.note),
      r.key,
      r.iv,
    );
    const commit2 = await Poseidon.hash(packCiphertext(ct2));
    expect(commit2.equals(walletNote!.commitment)).toBe(true);
  });
});
