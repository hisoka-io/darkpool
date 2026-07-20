import { Fr } from "@hisoka/wallets";
import { AbiCoder, randomBytes, toBigInt } from "ethers";
import { hashUniswapIntent } from "./intent.js";
import {
  UniswapSwapParams,
  UniswapSwapParamsInput,
  SwapType,
  RecipientIdentity,
} from "./types.js";

export interface SwapIntent {
  intentHash: Fr;
  encodedParams: string;
  deadline: bigint;
  // The salt actually used. Returned because the caller needs it to reconstruct the memo id, and
  // buildSwapIntent may have drawn it rather than received it.
  salt: bigint;
}

// Fresh return-note salt bound into the swap intent hash: unpredictable, so a griefer cannot pre-post the
// colliding public memo, and proof-bound, so a relayer cannot alter it. Nonzero and canonical (< field order).
export function randomSalt(): bigint {
  const s = toBigInt(randomBytes(32)) % Fr.MODULUS;
  return s === 0n ? 1n : s;
}

function recipientTuple(recipient: RecipientIdentity): [bigint, bigint] {
  return [recipient.ownerX, recipient.ownerY];
}

function encodeSwapParams(params: UniswapSwapParams): string {
  const coder = AbiCoder.defaultAbiCoder();
  switch (params.type) {
    case SwapType.ExactInputSingle:
      return coder.encode(
        [
          "tuple(address assetIn, address assetOut, uint24 fee, tuple(uint256 ownerX, uint256 ownerY) recipient, uint256 amountOutMin, uint256 salt)",
        ],
        [
          [
            params.assetIn,
            params.assetOut,
            params.fee,
            recipientTuple(params.recipient),
            params.amountOutMin,
            params.salt,
          ],
        ],
      );

    case SwapType.ExactInput:
      return coder.encode(
        [
          "tuple(bytes path, tuple(uint256 ownerX, uint256 ownerY) recipient, uint256 amountOutMin, uint256 salt)",
        ],
        [
          [
            params.path,
            recipientTuple(params.recipient),
            params.amountOutMin,
            params.salt,
          ],
        ],
      );

    case SwapType.ExactOutputSingle:
      return coder.encode(
        [
          "tuple(address assetIn, address assetOut, uint24 fee, tuple(uint256 ownerX, uint256 ownerY) recipient, uint256 amountOut, uint256 amountInMaximum, uint256 salt)",
        ],
        [
          [
            params.assetIn,
            params.assetOut,
            params.fee,
            recipientTuple(params.recipient),
            params.amountOut,
            params.amountInMaximum,
            params.salt,
          ],
        ],
      );

    case SwapType.ExactOutput:
      return coder.encode(
        [
          "tuple(bytes path, tuple(uint256 ownerX, uint256 ownerY) recipient, uint256 amountOut, uint256 amountInMaximum, uint256 salt)",
        ],
        [
          [
            params.path,
            recipientTuple(params.recipient),
            params.amountOut,
            params.amountInMaximum,
            params.salt,
          ],
        ],
      );

    default:
      throw new Error(`Unknown SwapType: ${(params as { type: number }).type}`);
  }
}

// `deadline` is a unix timestamp bound into intentHash and re-checked on-chain, so a captured proof cannot be
// executed at an attacker-chosen block. It must be within MAX_INTENT_LIFETIME of execution or the swap reverts.
export async function buildSwapIntent(
  params: UniswapSwapParamsInput,
  deadline: bigint,
): Promise<SwapIntent> {
  // Adding `salt: bigint` to any Unsalted<X> yields X; the cast only tells the compiler that, since a spread
  // does not distribute over a discriminated union.
  const salted = {
    ...params,
    salt: params.salt ?? randomSalt(),
  } as UniswapSwapParams;

  const intentHash = await hashUniswapIntent(salted, deadline);
  const encodedParams = encodeSwapParams(salted);
  return { intentHash, encodedParams, deadline, salt: salted.salt };
}
