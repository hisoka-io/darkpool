import { describe, it, expect, vi, beforeAll, afterEach } from "vitest";
import { inspect } from "node:util";
import { Wallet } from "ethers";
import { Base8, mulPointEscalar, subOrder } from "@zk-kit/baby-jubjub";
import { DarkAccount } from "../keys/DarkAccount";
import { Kdf } from "../crypto/Kdf";
import { isEvenY } from "../note/keys";

const MNEMONIC = "test test test test test test test test test test test junk";
const MESSAGE = "Hisoka Dark Account Setup";

describe("DarkAccount (Option A)", () => {
  afterEach(() => vi.restoreAllMocks());

  describe("root derivation", () => {
    it("derives one account deterministically from a mnemonic", async () => {
      const a = await DarkAccount.fromMnemonic(MNEMONIC);
      const b = await DarkAccount.fromMnemonic(MNEMONIC);
      expect((await a.getViewKey()).equals(await b.getViewKey())).toBe(true);
    });

    it("collapses case and whitespace variants of one mnemonic to one account", async () => {
      const canonical = await (
        await DarkAccount.fromMnemonic(MNEMONIC)
      ).getViewKey();
      const variants = [
        MNEMONIC.toUpperCase(),
        "Test test test test test test test test test test test junk",
        MNEMONIC.replace(/ /g, "  "),
      ];
      for (const variant of variants) {
        const view = await (
          await DarkAccount.fromMnemonic(variant)
        ).getViewKey();
        expect(view.equals(canonical)).toBe(true);
      }
    });

    it("derives one account deterministically from a signature", async () => {
      const eoa = Wallet.createRandom();
      const signature = await eoa.signMessage(MESSAGE);
      const a = await DarkAccount.fromSignature(signature);
      const b = await DarkAccount.fromSignature(signature);
      expect((await a.getViewKey()).equals(await b.getViewKey())).toBe(true);
    });

    it("rejects an invalid mnemonic", async () => {
      await expect(
        DarkAccount.fromMnemonic("not a valid mnemonic phrase at all"),
      ).rejects.toThrow(/mnemonic/i);
    });
  });

  describe("key-material redaction", () => {
    it("refuses JSON serialization and redacts on inspect", async () => {
      const account = await DarkAccount.fromMnemonic(MNEMONIC);
      await account.getViewKey();
      await account.getSelfSpendKey();

      expect(() => JSON.stringify(account)).toThrow();

      const printed = inspect(account);
      expect(printed).toContain("redacted");
      expect(printed).not.toMatch(/[0-9a-f]{16}/i);
    });
  });

  describe("view-key caching", () => {
    it("caches the view key after the first derivation", async () => {
      const account = await DarkAccount.fromMnemonic(MNEMONIC);
      const deriveSpy = vi.spyOn(Kdf, "derive");
      await account.getViewKey();
      await account.getViewKey();
      expect(deriveSpy).toHaveBeenCalledTimes(1);
    });
  });

  describe("Option A key surface", () => {
    let account: DarkAccount;
    beforeAll(async () => {
      account = await DarkAccount.fromMnemonic(MNEMONIC);
    });

    it("domain-separates view, self-spend, incoming, and self-ephemeral keys", async () => {
      const keys = [
        await account.getViewKey(),
        await account.getSelfSpendKey(),
        await account.getIncomingKey(0n),
        await account.getSelfEphemeral(0n),
      ];
      const distinct = new Set(keys.map((k) => k.toString()));
      expect(distinct.size).toBe(keys.length);
      for (const k of keys.slice(1)) expect(k.isZero()).toBe(false);
    });

    it("derives deterministic per-index incoming keys with matching public keys", async () => {
      const in1a = await account.getIncomingKey(1n);
      const in1b = await account.getIncomingKey(1n);
      const in2 = await account.getIncomingKey(2n);
      expect(in1a.equals(in1b)).toBe(true);
      expect(in1a.equals(in2)).toBe(false);

      const pub = await account.getIncomingPub(1n);
      const expected = mulPointEscalar(Base8, in1a.toBigInt());
      expect(pub[0]).toBe(expected[0]);
      expect(pub[1]).toBe(expected[1]);
    });

    it("derives deterministic per-index self ephemerals and a stable self-spend pub", async () => {
      const e1a = await account.getSelfEphemeral(1n);
      const e1b = await account.getSelfEphemeral(1n);
      const e2 = await account.getSelfEphemeral(2n);
      expect(e1a.equals(e1b)).toBe(true);
      expect(e1a.equals(e2)).toBe(false);

      const spendPub = await account.getSelfSpendPub();
      const expected = mulPointEscalar(
        Base8,
        (await account.getSelfSpendKey()).toBigInt(),
      );
      expect(spendPub[0]).toBe(expected[0]);
      expect(spendPub[1]).toBe(expected[1]);
    });

    it("keeps every derived scalar inside the prime-order subgroup", async () => {
      for (const i of [0n, 1n, 5n, 42n]) {
        const inKey = (await account.getIncomingKey(i)).toBigInt();
        const eph = (await account.getSelfEphemeral(i)).toBigInt();
        expect(inKey).toBeGreaterThan(0n);
        expect(inKey).toBeLessThan(subOrder);
        expect(eph).toBeGreaterThan(0n);
        expect(eph).toBeLessThan(subOrder);
      }
    });
  });

  describe("canonical even-y discovery tags", () => {
    it("rolls incoming and self tags to an even-y point", async () => {
      const account = await DarkAccount.fromMnemonic(MNEMONIC);
      const incoming = await account.canonicalIncomingAddress(0n);
      const self = await account.canonicalSelfTag(0n);

      expect(isEvenY(incoming.pub)).toBe(true);
      expect(isEvenY(self.pub)).toBe(true);
      expect(incoming.tag.toBigInt()).toBe(incoming.pub[0]);
      expect(self.tag.toBigInt()).toBe(self.pub[0]);
      expect(incoming.index).toBeGreaterThanOrEqual(0n);
      expect(self.index).toBeGreaterThanOrEqual(0n);
    });
  });
});
