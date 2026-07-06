import { describe, it, expect } from "vitest";
import { Fr } from "@aztec/foundation/fields";
import { Poseidon } from "../crypto/Poseidon.js";
import { PSI_DOMAIN } from "../crypto/constants.js";
import {
  leaf,
  packParents,
  unpackParents,
  type Note,
  type Parent,
} from "../note/note.js";

const CEK = new Fr(
  0x1fbbfa289c50b7ded032c85e5faa8b3790afc2fd059fd3d299294ff879a08bdan,
);

async function fixtureNote(): Promise<Note> {
  const psi = await Poseidon.hash([CEK, new Fr(PSI_DOMAIN)]);
  return {
    noteVersion: new Fr(1n),
    assetId: new Fr(0x1234567890123456789012345678901234567890n),
    noteType: new Fr(0n),
    conditionsHash: new Fr(0n),
    value: 100n,
    owner: new Fr(
      0x0bb44e077410f254c45a30b25976ce465e83511d7fda88f26e1296c6978eaf27n,
    ),
    psi,
    parents: new Fr(0n),
  };
}

describe("note leaf (plaintext-commit parity)", () => {
  it("KAT: fully-populated note leaf matches the Noir vector", async () => {
    const note = await fixtureNote();
    const value = await leaf(note);
    expect(value.toString()).toBe(
      "0x1bcd07739b701ccbd05dfb11bb4aaa428b200b37a7cbdc49d575b281b88930cc",
    );
  });

  it("psi input equals the shared-fixture psi", async () => {
    const psi = await Poseidon.hash([CEK, new Fr(PSI_DOMAIN)]);
    expect(psi.toString()).toBe(
      "0x0441d9b1006cd55062a6458b5dd1db14869f1a5c8fbc66f73032208c2b109956",
    );
  });

  it("rejects a value outside u128 range", async () => {
    const note = await fixtureNote();
    await expect(leaf({ ...note, value: 1n << 128n })).rejects.toThrow();
  });
});

describe("note parents packing (parity + round-trip)", () => {
  it("KAT: packs [2,4] to the Noir vector", () => {
    const pairs: [Parent, Parent] = [{ leafIndex: 2 }, { leafIndex: 4 }];
    expect(packParents(pairs).toBigInt()).toBe(0x400000002n);
  });

  it("round-trips [2,4]", () => {
    const pairs: [Parent, Parent] = [{ leafIndex: 2 }, { leafIndex: 4 }];
    expect(unpackParents(packParents(pairs))).toEqual(pairs);
  });

  it("deposit (no parents) packs to 0 and round-trips", () => {
    const deposit: [Parent, Parent] = [{ leafIndex: 0 }, { leafIndex: 0 }];
    const packed = packParents(deposit);
    expect(packed.toBigInt()).toBe(0n);
    expect(unpackParents(packed)).toEqual(deposit);
  });

  it("round-trips the max-u32 boundary", () => {
    const pairs: [Parent, Parent] = [
      { leafIndex: 0xffffffff },
      { leafIndex: 0xffffffff },
    ];
    expect(packParents(pairs).toBigInt()).toBe(0xffffffffffffffffn);
    expect(unpackParents(packParents(pairs))).toEqual(pairs);
  });

  it("rejects leaf_index >= 2^32 (no silent truncation)", () => {
    expect(() =>
      packParents([{ leafIndex: 2 ** 32 }, { leafIndex: 0 }]),
    ).toThrow();
  });
});
