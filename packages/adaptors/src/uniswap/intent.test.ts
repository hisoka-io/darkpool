import { describe, it, expect } from "vitest";
import { hashUniswapIntent } from "./intent.js";
import { encodePath } from "./path.js";
import { SwapType, UniswapSwapParams } from "./types.js";

const TEST_DEADLINE = 1_800_000_000n;

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
        salt: 789n,
      };

      const hash1 = await hashUniswapIntent(params, TEST_DEADLINE);
      const hash2 = await hashUniswapIntent(params, TEST_DEADLINE);

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
        salt: 789n,
      };

      const hash1 = await hashUniswapIntent(params, TEST_DEADLINE);
      const hash2 = await hashUniswapIntent(params, TEST_DEADLINE);

      expect(hash1.toString()).toBe(hash2.toString());
    });

    // Every golden below is asserted against Solidity _calculateIntentHash / _bindDeadline in evm-contracts
    // test/behaviors/UniswapIntentParity.test.ts; a drift here strands every swap-withdraw. All four swap
    // types are covered because each is folded by a different Solidity helper, so one type passing proves
    // nothing about the other three.
    const A_IN = "0x1111111111111111111111111111111111111111";
    const A_OUT = "0x2222222222222222222222222222222222222222";
    const RECIPIENT = { ownerX: 111n, ownerY: 222n };
    const SALT = 42n;

    const goldenCases: {
      name: string;
      params: UniswapSwapParams;
      bound: string;
    }[] = [
      {
        name: "ExactInputSingle",
        params: {
          type: SwapType.ExactInputSingle,
          assetIn: A_IN,
          assetOut: A_OUT,
          fee: 3000,
          amountOutMin: 1000n,
          recipient: RECIPIENT,
          salt: SALT,
        },
        bound:
          "0x0d001900c8416e2225422cbdb1423bb38e5c879e72b704aad02bebaed3c6106d",
      },
      {
        name: "ExactInput",
        params: {
          type: SwapType.ExactInput,
          path: encodePath([A_IN, A_OUT], [3000]),
          amountOutMin: 1000n,
          recipient: RECIPIENT,
          salt: SALT,
        },
        bound:
          "0x2eed82bc49420aa5efc2831ee05f9228c9232cb8f4f5a406f7bc6cbb5a0cd278",
      },
      {
        name: "ExactOutputSingle",
        params: {
          type: SwapType.ExactOutputSingle,
          assetIn: A_IN,
          assetOut: A_OUT,
          fee: 3000,
          amountOut: 1000n,
          amountInMaximum: 5000n,
          recipient: RECIPIENT,
          salt: SALT,
        },
        bound:
          "0x027e3c3bcd86a05f5ab06d003a1bef8ac0ce8f14956b2a4863ffb96681d1a398",
      },
      {
        name: "ExactOutput",
        params: {
          type: SwapType.ExactOutput,
          // ExactOutput encodes the path in reverse (tokenOut -> tokenIn).
          path: encodePath([A_OUT, A_IN], [3000]),
          amountOut: 1000n,
          amountInMaximum: 5000n,
          recipient: RECIPIENT,
          salt: SALT,
        },
        bound:
          "0x074dd110547b2d8b906b7a7d7baeb06a01450f41a0cc8778555ec179daa7e16d",
      },
    ];

    for (const c of goldenCases) {
      it(`${c.name} matches the committed Solidity golden (TS<->Sol parity)`, async () => {
        const h = await hashUniswapIntent(c.params, TEST_DEADLINE);
        expect("0x" + h.toBigInt().toString(16).padStart(64, "0")).toBe(
          c.bound,
        );
      });
    }
  });
});
