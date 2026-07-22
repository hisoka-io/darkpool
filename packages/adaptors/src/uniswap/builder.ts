import { Fr } from "@hisoka/wallets";
import { AbiCoder, randomBytes, toBigInt } from "ethers";
import { hashUniswapIntent } from "./intent.js";
import { AdaptorError } from "../errors.js";
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
  // Salt actually used (may be freshly drawn); caller needs it to rebuild the memo id.
  salt: bigint;
}

// Unpredictable + proof-bound salt so a griefer cannot pre-post the colliding memo. Nonzero, < field order.
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
      throw new AdaptorError(
        `Unknown SwapType: ${(params as { type: number }).type}`,
      );
  }
}

// deadline is bound into intentHash and re-checked on-chain, capping a captured proof's lifetime.
export async function buildSwapIntent(
  params: UniswapSwapParamsInput,
  deadline: bigint,
): Promise<SwapIntent> {
  // Cast needed: a spread does not distribute over the discriminated union.
  const salted = {
    ...params,
    salt: params.salt ?? randomSalt(),
  } as UniswapSwapParams;

  const intentHash = await hashUniswapIntent(salted, deadline);
  const encodedParams = encodeSwapParams(salted);
  return { intentHash, encodedParams, deadline, salt: salted.salt };
}
