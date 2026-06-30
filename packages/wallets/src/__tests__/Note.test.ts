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
  computeOwner,
  toBjjScalar,
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
    owner: new Fr(67890n),
    timelock: toFr(0n),
    hashlock: toFr(0n),
  };

  const note = new Note(samplePlaintext);
  const nk = new Fr(0xabcdefn);

  it("derives the Path-A nullifier as Poseidon(nk, commitment, leafIndex)", async () => {
    const commitment = new Fr(0x1234abcdn);
    const leafIndex = 5;

    const hash1 = await note.getNullifierHash(nk, commitment, leafIndex);
    const hash2 = await note.getNullifierHash(nk, commitment, leafIndex);
    expect(hash1).toBeInstanceOf(Fr);
    expect(hash1.equals(hash2)).toBe(true);

    const expected = await Poseidon.hash([
      nk,
      commitment,
      new Fr(BigInt(leafIndex)),
    ]);
    expect(hash1.equals(expected)).toBe(true);
  });

  it("binds the nullifier to the leaf position", async () => {
    const commitment = new Fr(0x1234abcdn);
    const atIndex5 = await note.getNullifierHash(nk, commitment, 5);
    const atIndex6 = await note.getNullifierHash(nk, commitment, 6);
    expect(atIndex5.equals(atIndex6)).toBe(false);
  });

  it("should throw an error for a negative value", () => {
    const invalidPlaintext = { ...samplePlaintext, value: toFr(1n) };
    invalidPlaintext.value.toBigInt = () => -1n;
    expect(() => new Note(invalidPlaintext)).toThrow(
      "Note value cannot be negative.",
    );
  });

  it("should throw for a note with a zero owner", () => {
    const zeroOwner = { ...samplePlaintext, owner: new Fr(0n) };
    expect(() => new Note(zeroOwner)).toThrow(
      "Note owner (spend-key commitment) must be non-zero",
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

    const owner = await computeOwner(await account.getPublicSpendKey());
    const note: NotePlaintext = {
      asset_id: addressToFr("0x0d500B1d8E8eF31E21C99d1Db9A6444d3ADf1270"),
      value: toFr(100n),
      secret: new Fr(12345n),
      owner,
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

describe("Transfer-memo detection is trial-decrypt (no on-chain tag)", () => {
  // Mirror the in-circuit 3-party encryption: S = a*ivk*C, int_bob = a*C, key = kdf(S.x). The recipient
  // recovers S = ivk*int_bob and decrypts; a wrong ivk yields a garbage key whose PKCS#7 padding fails.
  async function buildMemoEvent(ivkMod: bigint, ownerS: Point<bigint>) {
    const a = 424242n;
    const recipientP = mulPointEscalar(COMPLIANCE_PK, ivkMod); // ivk*C
    const sPoint = mulPointEscalar(recipientP, a); // a*ivk*C
    const { key, iv } = await kdfToAesKeyIV(new Fr(sPoint[0]));

    const memoNote: NotePlaintext = {
      asset_id: addressToFr("0x0d500B1d8E8eF31E21C99d1Db9A6444d3ADf1270"),
      value: toFr(40n),
      secret: toFr(0n),
      owner: await computeOwner(ownerS),
      timelock: toFr(0n),
      hashlock: toFr(0n),
    };
    const ct = await aes128Encrypt(packNotePlaintext(memoNote), key, iv);
    const packed = packCiphertext(ct);
    const commitment = await Poseidon.hash(packed);
    const intBob = mulPointEscalar(COMPLIANCE_PK, a); // a*C
    const memoEpk = mulPointEscalar(Base8, a);

    const event: UnprocessedEvent = {
      type: "NEW_MEMO",
      blockNumber: 1,
      txHash: "0x00",
      args: {
        leafIndex: 0n,
        commitment: "0x" + commitment.toBigInt().toString(16),
        epkX: memoEpk[0],
        epkY: memoEpk[1],
        packedCiphertext: packed.map((f) => "0x" + f.toBigInt().toString(16)),
        intermediateBobX: intBob[0],
        intermediateBobY: intBob[1],
      },
    };
    return { event, memoNote };
  }

  it("the recipient finds the memo via candidate iteration; a non-recipient finds nothing", async () => {
    const bob = await DarkAccount.fromMnemonic(MNEMONIC);
    const bobRepo = new KeyRepository(bob, COMPLIANCE_PK);
    await bobRepo.ensureIncomingLookahead(2);

    const ivkMod = toBjjScalar(await bob.getIncomingViewingKey(0n)).toBigInt();
    const { event, memoNote } = await buildMemoEvent(
      ivkMod,
      await bob.getPublicSpendKey(),
    );

    const found = await new NoteProcessor(bobRepo, COMPLIANCE_PK).process(
      event,
    );
    expect(found).not.toBeNull();
    expect(found!.isTransfer).toBe(true);
    expect(found!.note.owner.equals(memoNote.owner)).toBe(true);

    const eve = await DarkAccount.fromMnemonic(
      "legal winner thank year wave sausage worth useful legal winner thank yellow",
    );
    const eveRepo = new KeyRepository(eve, COMPLIANCE_PK);
    await eveRepo.ensureIncomingLookahead(2);
    const notFound = await new NoteProcessor(eveRepo, COMPLIANCE_PK).process(
      event,
    );
    expect(notFound).toBeNull();
  });
});
