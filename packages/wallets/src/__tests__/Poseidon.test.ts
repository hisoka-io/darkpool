import { describe, it, expect } from "vitest";
import { Fr } from "@aztec/foundation/fields";
import { Poseidon } from "../crypto/Poseidon";
import { toFr, addressToFr } from "../crypto/fields";

describe("Cryptographic Primitives", () => {
  describe("toFr", () => {
    it("should convert a bigint to an Fr element", () => {
      const fr = toFr(123n);
      expect(fr).toBeInstanceOf(Fr);
      expect(fr.toBigInt()).toBe(123n);
    });
  });

  describe("addressToFr", () => {
    it("should convert a valid address to an Fr element", () => {
      const address = "0x59D7B8bf8A85BC8439088746f9fad8A05924e847";
      const fr = addressToFr(address);
      expect(fr).toBeInstanceOf(Fr);
      expect(fr.toBigInt()).toBe(
        BigInt("0x59D7B8bf8A85BC8439088746f9fad8A05924e847"),
      );
    });

    it("should throw on an invalid address", () => {
      expect(() => addressToFr("0x123")).toThrow();
    });
  });

  describe("Poseidon", () => {
    it("should be deterministic", async () => {
      const input = [toFr(1), toFr(2), toFr(3)];
      const hash1 = await Poseidon.hash(input);
      const hash2 = await Poseidon.hash(input);
      expect(hash1.equals(hash2)).toBe(true);
    });

    it("should produce a different hash for different inputs", async () => {
      const input1 = [toFr(1), toFr(2)];
      const input2 = [toFr(2), toFr(1)];
      const hash1 = await Poseidon.hash(input1);
      const hash2 = await Poseidon.hash(input2);
      expect(hash1.equals(hash2)).toBe(false);
    });

    it("should produce a known hash output", async () => {
      const input = [toFr(1), toFr(2)];
      const expectedHash = new Fr(
        0x038682aa1cb5ae4e0a3f13da432a95c77c5c111f6f030faf9cad641ce1ed7383n,
      );
      const actualHash = await Poseidon.hash(input);
      expect(actualHash.equals(expectedHash)).toBe(true);
    });

    it("should not collide on random inputs", async () => {
      const inputs = new Set<string>();
      for (let i = 0; i < 1000; i++) {
        const randBuffer = new Uint32Array(2);
        crypto.getRandomValues(randBuffer);
        const rand1 = toFr(
          (BigInt(randBuffer[0]) * BigInt(randBuffer[1])) % Fr.MODULUS,
        );
        const rand2 = toFr(BigInt(randBuffer[0]) + (BigInt(i) % Fr.MODULUS));
        const hash = await Poseidon.hash([rand1, rand2]);
        const hashStr = hash.toString();
        expect(inputs.has(hashStr)).toBe(false); // Now no collisions
        inputs.add(hashStr);
      }
    });
  });
});
