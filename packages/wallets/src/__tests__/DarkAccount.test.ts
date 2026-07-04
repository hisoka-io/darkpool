import { describe, it, expect, vi, beforeAll, afterEach } from "vitest";
import { inspect } from "node:util";
import { Wallet } from "ethers";
import { Base8, mulPointEscalar, subOrder } from "@zk-kit/baby-jubjub";
import { DarkAccount } from "../keys/DarkAccount";
import { Kdf } from "../crypto/Kdf";

describe("DarkAccount", () => {
  const testMnemonic =
    "test test test test test test test test test test test junk";
  const testMessage = "Hisoka Dark Account Setup";

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe("Core Key Derivation", () => {
    it("should create an account deterministically from a mnemonic", async () => {
      const account1 = await DarkAccount.fromMnemonic(testMnemonic);
      const account2 = await DarkAccount.fromMnemonic(testMnemonic);
      const sk1 = await account1.getSpendKey();
      const sk2 = await account2.getSpendKey();
      expect(sk1.equals(sk2)).toBe(true);
    });

    it("derives the identical account from case and whitespace variants of one mnemonic", async () => {
      const canonical = await DarkAccount.fromMnemonic(testMnemonic);
      const expected = await canonical.getSpendKey();

      // ethers accepts these non-canonical renderings and canonicalizes them, but their raw strings
      // differ; seeding from the raw input would silently derive divergent accounts.
      const variants = [
        testMnemonic.toUpperCase(),
        "Test test test test test test test test test test test junk",
        testMnemonic.replace(/ /g, "  "),
      ];
      for (const variant of variants) {
        const account = await DarkAccount.fromMnemonic(variant);
        const sk = await account.getSpendKey();
        expect(sk.equals(expected)).toBe(true);
      }
    });

    it("refuses to serialize or print key material", async () => {
      const account = await DarkAccount.fromMnemonic(testMnemonic);
      await account.getSpendKey();
      await account.getViewKey();
      await account.getNullifyingKey();

      expect(() => JSON.stringify(account)).toThrow();

      const printed = inspect(account);
      expect(printed).toContain("redacted");
      expect(printed).not.toMatch(/[0-9a-f]{16}/i);
    });

    it("should create an account deterministically from a signature", async () => {
      const eoa = Wallet.createRandom();
      const signature = await eoa.signMessage(testMessage);
      const account1 = await DarkAccount.fromSignature(signature);
      const account2 = await DarkAccount.fromSignature(signature);
      const sk1 = await account1.getSpendKey();
      const sk2 = await account2.getSpendKey();
      expect(sk1.equals(sk2)).toBe(true);
    });

    it("should derive sk_spend and sk_view correctly", async () => {
      const account = await DarkAccount.fromMnemonic(testMnemonic);
      const sk_spend = await account.getSpendKey();
      const sk_view = await account.getViewKey();

      expect(sk_spend).toBeDefined();
      expect(sk_view).toBeDefined();
      expect(sk_spend.equals(sk_view)).toBe(false);
      expect(sk_spend.isZero()).toBe(false);
    });

    it("should cache master keys after the first call", async () => {
      const account = await DarkAccount.fromMnemonic(testMnemonic);
      const deriveSpy = vi.spyOn(Kdf, "derive");

      await account.getSpendKey();
      await account.getViewKey();

      expect(deriveSpy).toHaveBeenCalledTimes(2);

      // Cached: second calls must not re-derive master keys.
      await account.getSpendKey();
      await account.getViewKey();
      expect(deriveSpy).toHaveBeenCalledTimes(2);
    });
  });

  describe("Optimized Viewing Key Branch", () => {
    let account: DarkAccount;
    beforeAll(async () => {
      account = await DarkAccount.fromMnemonic(testMnemonic);
    });

    it("should derive deterministic per-transaction incoming viewing keys (ivk)", async () => {
      const ivk1_a = await account.getIncomingViewingKey(1n);
      const ivk1_b = await account.getIncomingViewingKey(1n);
      const ivk2 = await account.getIncomingViewingKey(2n);
      expect(ivk1_a.equals(ivk1_b)).toBe(true);
      expect(ivk1_a.equals(ivk2)).toBe(false);
    });

    it("should derive deterministic per-transaction ephemeral outgoing keys (esk)", async () => {
      const esk1_a = await account.getEphemeralOutgoingKey(1n);
      const esk1_b = await account.getEphemeralOutgoingKey(1n);
      const esk2 = await account.getEphemeralOutgoingKey(2n);
      expect(esk1_a.equals(esk1_b)).toBe(true);
      expect(esk1_a.equals(esk2)).toBe(false);
    });

    it("should derive different ivk and esk for the same index due to different domain separators", async () => {
      const ivk = await account.getIncomingViewingKey(123n);
      const esk = await account.getEphemeralOutgoingKey(123n);
      expect(ivk.equals(esk)).toBe(false);
    });

    it("should derive a valid public Incoming Viewing Key", async () => {
      const IVK = await account.getPublicIncomingViewingKey(1n);
      expect(IVK).toBeDefined();
      expect(IVK.length).toBe(2);
      expect(typeof IVK[0]).toBe("bigint");
    });

    it("should derive a valid public Ephemeral Outgoing Key", async () => {
      const EPK = await account.getPublicEphemeralOutgoingKey(1n);
      expect(EPK).toBeDefined();
      expect(EPK.length).toBe(2);
      expect(typeof EPK[0]).toBe("bigint");
    });
  });

  describe("KH-3 invariant (scalar in sub-order, public = Base8 * scalar)", () => {
    it("derives reduced view/ephemeral scalars consistent with their public keys", async () => {
      const account = await DarkAccount.fromMnemonic(testMnemonic);
      for (const i of [0n, 1n, 5n, 42n]) {
        const ivk = (await account.getIncomingViewingKey(i)).toBigInt();
        expect(ivk).toBeGreaterThan(0n);
        expect(ivk).toBeLessThan(subOrder);
        const ivkPub = await account.getPublicIncomingViewingKey(i);
        const expIvkPub = mulPointEscalar(Base8, ivk);
        expect(ivkPub[0]).toBe(expIvkPub[0]);
        expect(ivkPub[1]).toBe(expIvkPub[1]);

        const esk = (await account.getEphemeralOutgoingKey(i)).toBigInt();
        expect(esk).toBeGreaterThan(0n);
        expect(esk).toBeLessThan(subOrder);
        const eskPub = await account.getPublicEphemeralOutgoingKey(i);
        const expEskPub = mulPointEscalar(Base8, esk);
        expect(eskPub[0]).toBe(expEskPub[0]);
        expect(eskPub[1]).toBe(expEskPub[1]);
      }
    });
  });
});
