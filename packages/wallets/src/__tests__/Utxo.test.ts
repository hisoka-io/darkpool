import { describe, it, expect } from "vitest";
import { Fr } from "@aztec/foundation/fields";
import { Utxo } from "../utxo/Utxo";
import { Note } from "../note/note";

// Deposit-fixture anchors (gen_v2_fixtures.ts): a self note of value 100 to owner_self.
const ASSET = new Fr(0x1234567890123456789012345678901234567890n);
const OWNER_SELF = new Fr(
  0x2874ae964d8b283e2f521a7f14125fc92747bb9770139b8d4b70ee09e2d83785n,
);
const DEPOSIT_PSI = new Fr(
  0x0981a88f9e119b057498a4ab99ed5379a1ea91c642454fc0c07aacc1f5cd5731n,
);
const NULLIFIER_AT_0 = new Fr(
  0x2761654f0b4e9f47ac9bafe900c723ead042a888da718a34b6ecc8036850755en,
);

function depositNote(overrides: Partial<Note> = {}): Note {
  return {
    noteVersion: new Fr(1n),
    assetId: ASSET,
    noteType: new Fr(0n),
    conditionsHash: new Fr(0n),
    value: 100n,
    owner: OWNER_SELF,
    psi: DEPOSIT_PSI,
    parents: new Fr(0n),
    ...overrides,
  };
}

describe("Utxo", () => {
  it("computes the deposit-fixture nullifier at leaf index 0", async () => {
    const note = new Utxo(depositNote());
    const nullifier = await note.getNullifierHash(DEPOSIT_PSI, 0);
    expect(nullifier.equals(NULLIFIER_AT_0)).toBe(true);
  });

  it("binds the nullifier to the leaf position", async () => {
    const note = new Utxo(depositNote());
    const at0 = await note.getNullifierHash(DEPOSIT_PSI, 0);
    const at1 = await note.getNullifierHash(DEPOSIT_PSI, 1);
    expect(at0.equals(at1)).toBe(false);
  });

  it("rejects a value outside u128 range", () => {
    expect(() => new Utxo(depositNote({ value: 1n << 128n }))).toThrow(/u128/);
  });

  it("rejects a zero owner", () => {
    expect(() => new Utxo(depositNote({ owner: new Fr(0n) }))).toThrow(/owner/);
  });

  // asset_id must fit an EVM address; the guard must inspect the high 12 bytes (checking low 20 catches nothing).
  it("rejects an assetId wider than 160 bits", () => {
    const oversized = new Fr(
      (1n << 160n) | 0x1234567890123456789012345678901234567890n,
    );
    expect(() => new Utxo(depositNote({ assetId: oversized }))).toThrow(
      /160 bits/,
    );
  });

  it("accepts an assetId that fits an EVM address", () => {
    expect(() => new Utxo(depositNote({ assetId: ASSET }))).not.toThrow();
    expect(() => new Utxo(depositNote({ assetId: new Fr(0n) }))).not.toThrow();
    expect(
      () => new Utxo(depositNote({ assetId: new Fr((1n << 160n) - 1n) })),
    ).not.toThrow();
  });
});
