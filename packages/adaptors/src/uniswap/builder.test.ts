import { describe, it, expect } from "vitest";
import { AbiCoder } from "ethers";
import { buildSwapIntent } from "./builder.js";
import { hashUniswapIntent } from "./intent.js";
import { encodePath } from "./path.js";
import {
  SwapType,
  UniswapSwapParams,
  ExactInputSingleParams,
  ExactInputParams,
  ExactOutputSingleParams,
  ExactOutputParams,
} from "./types.js";

const TEST_DEADLINE = 1_800_000_000n;

const WETH = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2";
const USDC = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";
const WBTC = "0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599";

const recipient = { ownerX: 123n, ownerY: 456n };
const salt = 789n;

const coder = AbiCoder.defaultAbiCoder();

const exactInputSingle: ExactInputSingleParams = {
  type: SwapType.ExactInputSingle,
  assetIn: WETH,
  assetOut: USDC,
  fee: 500,
  recipient,
  amountOutMin: 1000n,
  salt,
};

const exactInput: ExactInputParams = {
  type: SwapType.ExactInput,
  path: encodePath([WETH, USDC], [3000]),
  recipient,
  amountOutMin: 2000n,
  salt,
};

const exactOutputSingle: ExactOutputSingleParams = {
  type: SwapType.ExactOutputSingle,
  assetIn: WETH,
  assetOut: USDC,
  fee: 500,
  recipient,
  amountOut: 3000n,
  amountInMaximum: 9000n,
  salt,
};

const exactOutput: ExactOutputParams = {
  type: SwapType.ExactOutput,
  path: encodePath([WBTC, USDC, WETH], [500, 3000]),
  recipient,
  amountOut: 4000n,
  amountInMaximum: 12000n,
  salt,
};

const SINGLE_IN_TUPLE =
  "tuple(address assetIn, address assetOut, uint24 fee, tuple(uint256 ownerX, uint256 ownerY) recipient, uint256 amountOutMin, uint256 salt)";
const MULTI_IN_TUPLE =
  "tuple(bytes path, tuple(uint256 ownerX, uint256 ownerY) recipient, uint256 amountOutMin, uint256 salt)";
const SINGLE_OUT_TUPLE =
  "tuple(address assetIn, address assetOut, uint24 fee, tuple(uint256 ownerX, uint256 ownerY) recipient, uint256 amountOut, uint256 amountInMaximum, uint256 salt)";
const MULTI_OUT_TUPLE =
  "tuple(bytes path, tuple(uint256 ownerX, uint256 ownerY) recipient, uint256 amountOut, uint256 amountInMaximum, uint256 salt)";

function handRolled(params: UniswapSwapParams): string {
  switch (params.type) {
    case SwapType.ExactInputSingle:
      return coder.encode(
        [SINGLE_IN_TUPLE],
        [
          [
            params.assetIn,
            params.assetOut,
            params.fee,
            [params.recipient.ownerX, params.recipient.ownerY],
            params.amountOutMin,
            params.salt,
          ],
        ],
      );
    case SwapType.ExactInput:
      return coder.encode(
        [MULTI_IN_TUPLE],
        [
          [
            params.path,
            [params.recipient.ownerX, params.recipient.ownerY],
            params.amountOutMin,
            params.salt,
          ],
        ],
      );
    case SwapType.ExactOutputSingle:
      return coder.encode(
        [SINGLE_OUT_TUPLE],
        [
          [
            params.assetIn,
            params.assetOut,
            params.fee,
            [params.recipient.ownerX, params.recipient.ownerY],
            params.amountOut,
            params.amountInMaximum,
            params.salt,
          ],
        ],
      );
    case SwapType.ExactOutput:
      return coder.encode(
        [MULTI_OUT_TUPLE],
        [
          [
            params.path,
            [params.recipient.ownerX, params.recipient.ownerY],
            params.amountOut,
            params.amountInMaximum,
            params.salt,
          ],
        ],
      );
    default:
      throw new Error("unreachable");
  }
}

describe("buildSwapIntent", () => {
  it("ExactInputSingle: encodedParams matches hand-rolled, round-trips, intentHash matches", async () => {
    const built = await buildSwapIntent(exactInputSingle, TEST_DEADLINE);

    expect(built.encodedParams).toBe(handRolled(exactInputSingle));

    const [decoded] = coder.decode([SINGLE_IN_TUPLE], built.encodedParams);
    expect(decoded.assetIn).toBe(exactInputSingle.assetIn);
    expect(decoded.assetOut).toBe(exactInputSingle.assetOut);
    expect(decoded.fee).toBe(BigInt(exactInputSingle.fee));
    expect(decoded.recipient.ownerX).toBe(recipient.ownerX);
    expect(decoded.recipient.ownerY).toBe(recipient.ownerY);
    expect(decoded.amountOutMin).toBe(exactInputSingle.amountOutMin);
    expect(decoded.salt).toBe(exactInputSingle.salt);

    const direct = await hashUniswapIntent(exactInputSingle, TEST_DEADLINE);
    expect(built.intentHash.toString()).toBe(direct.toString());
  });

  it("ExactInput: encodedParams matches hand-rolled, round-trips, intentHash matches", async () => {
    const built = await buildSwapIntent(exactInput, TEST_DEADLINE);

    expect(built.encodedParams).toBe(handRolled(exactInput));

    const [decoded] = coder.decode([MULTI_IN_TUPLE], built.encodedParams);
    expect(decoded.path).toBe(exactInput.path);
    expect(decoded.recipient.ownerX).toBe(recipient.ownerX);
    expect(decoded.recipient.ownerY).toBe(recipient.ownerY);
    expect(decoded.amountOutMin).toBe(exactInput.amountOutMin);
    expect(decoded.salt).toBe(exactInput.salt);

    const direct = await hashUniswapIntent(exactInput, TEST_DEADLINE);
    expect(built.intentHash.toString()).toBe(direct.toString());
  });

  it("ExactOutputSingle: encodedParams matches hand-rolled, round-trips, intentHash matches", async () => {
    const built = await buildSwapIntent(exactOutputSingle, TEST_DEADLINE);

    expect(built.encodedParams).toBe(handRolled(exactOutputSingle));

    const [decoded] = coder.decode([SINGLE_OUT_TUPLE], built.encodedParams);
    expect(decoded.assetIn).toBe(exactOutputSingle.assetIn);
    expect(decoded.assetOut).toBe(exactOutputSingle.assetOut);
    expect(decoded.fee).toBe(BigInt(exactOutputSingle.fee));
    expect(decoded.recipient.ownerX).toBe(recipient.ownerX);
    expect(decoded.recipient.ownerY).toBe(recipient.ownerY);
    expect(decoded.amountOut).toBe(exactOutputSingle.amountOut);
    expect(decoded.amountInMaximum).toBe(exactOutputSingle.amountInMaximum);
    expect(decoded.salt).toBe(exactOutputSingle.salt);

    const direct = await hashUniswapIntent(exactOutputSingle, TEST_DEADLINE);
    expect(built.intentHash.toString()).toBe(direct.toString());
  });

  it("ExactOutput: encodedParams matches hand-rolled, round-trips, intentHash matches", async () => {
    const built = await buildSwapIntent(exactOutput, TEST_DEADLINE);

    expect(built.encodedParams).toBe(handRolled(exactOutput));

    const [decoded] = coder.decode([MULTI_OUT_TUPLE], built.encodedParams);
    expect(decoded.path).toBe(exactOutput.path);
    expect(decoded.recipient.ownerX).toBe(recipient.ownerX);
    expect(decoded.recipient.ownerY).toBe(recipient.ownerY);
    expect(decoded.amountOut).toBe(exactOutput.amountOut);
    expect(decoded.amountInMaximum).toBe(exactOutput.amountInMaximum);
    expect(decoded.salt).toBe(exactOutput.salt);

    const direct = await hashUniswapIntent(exactOutput, TEST_DEADLINE);
    expect(built.intentHash.toString()).toBe(direct.toString());
  });
});

// Salt blocks a griefer front-running the pending swap's memo id (else the swap reverts on MemoCollision).
describe("buildSwapIntent salt entropy", () => {
  const { salt: _drop, ...unsalted } = exactInputSingle;

  it("draws a fresh salt when none is supplied", async () => {
    const a = await buildSwapIntent(unsalted, TEST_DEADLINE);
    const b = await buildSwapIntent(unsalted, TEST_DEADLINE);

    expect(a.salt).not.toBe(b.salt);
    expect(a.intentHash.toString()).not.toBe(b.intentHash.toString());
  });

  it("draws a salt with real entropy, not a small counter", async () => {
    for (let i = 0; i < 8; i++) {
      const { salt } = await buildSwapIntent(unsalted, TEST_DEADLINE);
      expect(salt).toBeGreaterThan(1n << 200n);
    }
  });

  it("returns the drawn salt so the caller can reconstruct the memo id", async () => {
    const built = await buildSwapIntent(unsalted, TEST_DEADLINE);
    const rebuilt = await hashUniswapIntent(
      { ...unsalted, salt: built.salt },
      TEST_DEADLINE,
    );
    expect(built.intentHash.toString()).toBe(rebuilt.toString());
  });

  it("still honours an explicitly supplied salt", async () => {
    const built = await buildSwapIntent(exactInputSingle, TEST_DEADLINE);
    expect(built.salt).toBe(salt);
  });
});
