import { describe, it, expect } from "vitest";
import { Kdf } from "../crypto/Kdf";
import { toFr, stringToFr } from "../crypto/fields";

describe("Kdf", () => {
  const sk_root = toFr(123456789123456789n);
  const nonce = toFr(42n);

  describe("stringToFr", () => {
    it("should be deterministic", async () => {
      const fr1 = await stringToFr("hisoka.spend");
      const fr2 = await stringToFr("hisoka.spend");
      expect(fr1.equals(fr2)).toBe(true);
    });
  });

  describe("derive", () => {
    it("should derive deterministically without nonce", async () => {
      const sk_spend1 = await Kdf.derive("hisoka.spend", sk_root);
      const sk_spend2 = await Kdf.derive("hisoka.spend", sk_root);
      expect(sk_spend1.equals(sk_spend2)).toBe(true);
    });

    it("should derive different keys for different purposes", async () => {
      const sk_spend = await Kdf.derive("hisoka.spend", sk_root);
      const sk_view = await Kdf.derive("hisoka.view", sk_root);
      expect(sk_spend.equals(sk_view)).toBe(false);
    });

    it("should derive a key different from the master key", async () => {
      const sk_spend = await Kdf.derive("hisoka.spend", sk_root);
      expect(sk_spend.equals(sk_root)).toBe(false);
    });

    it("should derive different with nonce", async () => {
      const noNonce = await Kdf.derive("hisoka.view", sk_root);
      const withNonce = await Kdf.derive("hisoka.view", sk_root, nonce);
      expect(noNonce.equals(withNonce)).toBe(false);
    });

    // New: Edge - nonce=0 same as no nonce?
    it("should treat missing nonce as 0", async () => {
      const noNonce = await Kdf.derive("test", sk_root);
      const zeroNonce = await Kdf.derive("test", sk_root, toFr(0n));
      expect(noNonce.equals(zeroNonce)).toBe(true);
    });
  });
});
