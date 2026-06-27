import { describe, it, expect } from "vitest";
import { Fr } from "@aztec/foundation/fields";
import { Note } from "../utxo/Note";
import { NotePlaintext } from "../crypto";
import { Poseidon } from "../crypto/Poseidon";
import { toFr, addressToFr } from "../crypto/fields";

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
});
