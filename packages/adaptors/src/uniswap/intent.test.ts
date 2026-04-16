import { describe, it, expect } from "vitest";
import { hashUniswapIntent } from "./intent.js";
import { encodePath } from "./path.js";
import { SwapType, UniswapSwapParams } from "./types.js";

describe("Uniswap Adaptor Logic", () => {
  describe("encodePath", () => {
    it("should correctly encode a single hop path", () => {
      const tokenA = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2";
      const tokenB = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";
      const fee = 3000;

      const encoded = encodePath([tokenA, tokenB], [fee]);
      expect(encoded).toMatch(/^0x[0-9a-fA-F]+$/);
      // 20 bytes (40 chars) + 3 bytes (6 chars) + 20 bytes (40 chars) + "0x" (2 chars) = 88 chars
      expect(encoded.length).toBe(88);
    });

    it("should throw if tokens and fees length mismatch", () => {
      expect(() => encodePath(["0xA", "0xB"], [])).toThrow();
    });
  });

  describe("hashUniswapIntent", () => {
    it("should produce a deterministic hash for ExactInputSingle", async () => {
      const params: UniswapSwapParams = {
        type: SwapType.ExactInputSingle,
        assetIn: "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
        assetOut: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
        fee: 500,
        recipient: { ownerX: 123n, ownerY: 456n },
        amountOutMin: 1000n,
      };

      const hash1 = await hashUniswapIntent(params);
      const hash2 = await hashUniswapIntent(params);

      expect(hash1.toString()).toBe(hash2.toString());
      expect(hash1.isZero()).toBe(false);
    });

    it("should produce a deterministic hash for ExactInput (Multihop)", async () => {
      const path = encodePath(
        [
          "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
          "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
        ],
        [3000],
      );
      const params: UniswapSwapParams = {
        type: SwapType.ExactInput,
        path: path,
        recipient: { ownerX: 123n, ownerY: 456n },
        amountOutMin: 1000n,
      };

      const hash1 = await hashUniswapIntent(params);
      const hash2 = await hashUniswapIntent(params);

      expect(hash1.toString()).toBe(hash2.toString());
    });
  });
});
