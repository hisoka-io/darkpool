import { Fr } from "@hisoka/wallets";
import { AbiCoder, randomBytes, toBigInt } from "ethers";
import { hashUniswapIntent } from "./intent.js";
import { UniswapSwapParams, SwapType, RecipientIdentity } from "./types.js";

export interface SwapIntent {
  intentHash: Fr;
  encodedParams: string;
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
      throw new Error(
        `Unknown SwapType: ${(params as { type: number }).type}`,
      );
  }
}

export async function buildSwapIntent(
  params: UniswapSwapParams,
): Promise<SwapIntent> {
  const intentHash = await hashUniswapIntent(params);
  const encodedParams = encodeSwapParams(params);
  return { intentHash, encodedParams };
}
