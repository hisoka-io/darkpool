import { Fr } from "@hisoka/wallets";
import { AbiCoder } from "ethers";
import { hashUniswapIntent } from "./intent.js";
import { UniswapSwapParams, SwapType, RecipientIdentity } from "./types.js";

export interface SwapIntent {
  intentHash: Fr;
  encodedParams: string;
}

function recipientTuple(
  recipient: RecipientIdentity,
): [bigint, bigint, bigint] {
  return [recipient.ownerX, recipient.ownerY, recipient.claimerOwner];
}

function encodeSwapParams(params: UniswapSwapParams): string {
  const coder = AbiCoder.defaultAbiCoder();
  switch (params.type) {
    case SwapType.ExactInputSingle:
      return coder.encode(
        [
          "tuple(address assetIn, address assetOut, uint24 fee, tuple(uint256 ownerX, uint256 ownerY, uint256 claimerOwner) recipient, uint256 amountOutMin)",
        ],
        [
          [
            params.assetIn,
            params.assetOut,
            params.fee,
            recipientTuple(params.recipient),
            params.amountOutMin,
          ],
        ],
      );

    case SwapType.ExactInput:
      return coder.encode(
        [
          "tuple(bytes path, tuple(uint256 ownerX, uint256 ownerY, uint256 claimerOwner) recipient, uint256 amountOutMin)",
        ],
        [[params.path, recipientTuple(params.recipient), params.amountOutMin]],
      );

    case SwapType.ExactOutputSingle:
      return coder.encode(
        [
          "tuple(address assetIn, address assetOut, uint24 fee, tuple(uint256 ownerX, uint256 ownerY, uint256 claimerOwner) recipient, uint256 amountOut, uint256 amountInMaximum)",
        ],
        [
          [
            params.assetIn,
            params.assetOut,
            params.fee,
            recipientTuple(params.recipient),
            params.amountOut,
            params.amountInMaximum,
          ],
        ],
      );

    case SwapType.ExactOutput:
      return coder.encode(
        [
          "tuple(bytes path, tuple(uint256 ownerX, uint256 ownerY, uint256 claimerOwner) recipient, uint256 amountOut, uint256 amountInMaximum)",
        ],
        [
          [
            params.path,
            recipientTuple(params.recipient),
            params.amountOut,
            params.amountInMaximum,
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
