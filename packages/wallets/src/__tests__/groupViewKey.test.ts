import { describe, expect, it } from "vitest";
import { Fr } from "@aztec/foundation/fields";
import { Point } from "@zk-kit/baby-jubjub";
import { DarkAccount } from "../keys/DarkAccount.js";
import { deriveGroupViewKey } from "../frost/groupViewKey.js";
import { isEvenY, publicKey } from "../note/keys.js";
import {
  deriveMultisigIncomingKey,
  deriveSelfEph,
} from "../frost/multisigNote.js";

const MNEMONIC = "test test test test test test test test test test test junk";
const OTHER =
  "legal winner thank year wave sausage worth useful legal winner thank yellow";

function gpkFrom(seed: bigint): Point<bigint> {
  return publicKey(new Fr(seed));
}

describe("group view key derived from the creator's seed", () => {
  it("is reproducible from the seed and the public gpk alone", async () => {
    const gpk = gpkFrom(0x1234n);
    const a = await deriveGroupViewKey(
      await DarkAccount.fromMnemonic(MNEMONIC),
      gpk,
    );
    // A fresh account object, as a reinstall would build: nothing carried but the mnemonic.
    const b = await deriveGroupViewKey(
      await DarkAccount.fromMnemonic(MNEMONIC),
      gpk,
    );
    expect(b.v.toString()).toBe(a.v.toString());
    expect(b.roll).toBe(a.roll);
    expect(b.V[0]).toBe(a.V[0]);
  });

  it("always lands on an even-y view point, because V.x is a discovery tag", async () => {
    for (const seed of [0x1n, 0x99n, 0xabcdefn, 0x5f5f5fn]) {
      const key = await deriveGroupViewKey(
        await DarkAccount.fromMnemonic(MNEMONIC),
        gpkFrom(seed),
      );
      expect(isEvenY(key.V)).toBe(true);
      expect(publicKey(key.v)[0]).toBe(key.V[0]);
    }
  });

  it("gives two groups under one seed independent view keys", async () => {
    const account = await DarkAccount.fromMnemonic(MNEMONIC);
    const one = await deriveGroupViewKey(account, gpkFrom(0x1111n));
    const two = await deriveGroupViewKey(account, gpkFrom(0x2222n));
    expect(one.v.toString()).not.toBe(two.v.toString());
  });

  it("gives two creators the same group different view keys", async () => {
    const gpk = gpkFrom(0x1234n);
    const mine = await deriveGroupViewKey(
      await DarkAccount.fromMnemonic(MNEMONIC),
      gpk,
    );
    const theirs = await deriveGroupViewKey(
      await DarkAccount.fromMnemonic(OTHER),
      gpk,
    );
    expect(mine.v.toString()).not.toBe(theirs.v.toString());
  });

  it("feeds the discovery keys, so a creator restore recovers the group's tags", async () => {
    const gpk = gpkFrom(0x1234n);
    const before = await deriveGroupViewKey(
      await DarkAccount.fromMnemonic(MNEMONIC),
      gpk,
    );
    const selfBefore = await deriveSelfEph(before.v, 1n, 7n);
    const inBefore = await deriveMultisigIncomingKey(before.v, 3n);

    // Everything is gone except the mnemonic and the group's public key.
    const after = await deriveGroupViewKey(
      await DarkAccount.fromMnemonic(MNEMONIC),
      gpk,
    );
    const selfAfter = await deriveSelfEph(after.v, 1n, 7n);
    const inAfter = await deriveMultisigIncomingKey(after.v, 3n);

    expect(selfAfter.eph.toString()).toBe(selfBefore.eph.toString());
    expect(inAfter.toString()).toBe(inBefore.toString());
  });

  it("is a BabyJubJub subgroup scalar, so it can drive an ECDH", async () => {
    const key = await deriveGroupViewKey(
      await DarkAccount.fromMnemonic(MNEMONIC),
      gpkFrom(0x777n),
    );
    expect(key.v.toBigInt()).toBeGreaterThan(0n);
    // publicKey() asserts subgroup membership internally; reaching here at all is the check.
    expect(publicKey(key.v)[1] % 2n).toBe(0n);
  });
});

describe("the ceremony uses the derived key when a creator is supplied", () => {
  it("yields a group whose view key the creator can recompute from the seed alone", async () => {
    const { frostAccountDkg } = await import("../unsafe-sim/accountDkg.js");
    const creator = await DarkAccount.fromMnemonic(MNEMONIC);
    const account = await frostAccountDkg(3, 2, 0x1234n, creator);

    // Everything is gone except the mnemonic and the group's PUBLIC key.
    const recovered = await deriveGroupViewKey(
      await DarkAccount.fromMnemonic(MNEMONIC),
      account.gpk,
    );
    expect(recovered.v.toBigInt()).toBe(account.viewKey);
    expect(recovered.V[0]).toBe(account.viewPub[0]);
  });

  it("without a creator the key is sampled and no seed reproduces it", async () => {
    const { frostAccountDkg } = await import("../unsafe-sim/accountDkg.js");
    const a = await frostAccountDkg(3, 2, 0x1234n);
    const b = await frostAccountDkg(3, 2, 0x1234n);
    expect(a.viewKey).not.toBe(b.viewKey);
  });
});
