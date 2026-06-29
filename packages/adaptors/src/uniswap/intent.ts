import { Poseidon, addressToFr, toFr, Fr } from "@hisoka/wallets";
import { UniswapSwapParams, SwapType } from "./types.js";
import { keccak256 } from "ethers";

function hashBytesToField(data: string): Fr {
  const hashHex = keccak256(data);
  const reduced = BigInt(hashHex) % Fr.MODULUS;
  return new Fr(reduced);
}

/**
 * Compute Poseidon2 intent hash binding a withdrawal proof to swap parameters.
 * Field ordering MUST match Solidity UniswapAdaptor._calculateIntentHash() exactly:
 *
 *   ExactInputSingle(0): [type, assetIn, assetOut, fee, amountOutMin, ownerX, ownerY, claimerOwner]  (8 fields)
 *   ExactInput(1):       [type, keccak256(path) % PRIME, amountOutMin, ownerX, ownerY, claimerOwner]  (6 fields)
 *   ExactOutputSingle(2):[type, assetIn, assetOut, fee, amountOut, amountInMax, ownerX, ownerY, claimerOwner]  (9 fields)
 *   ExactOutput(3):      [type, keccak256(path) % PRIME, amountOut, amountInMax, ownerX, ownerY, claimerOwner]  (7 fields)
 */
export async function hashUniswapIntent(
  params: UniswapSwapParams,
): Promise<Fr> {
  switch (params.type) {
    case SwapType.ExactInputSingle:
      return await Poseidon.hash([
        toFr(params.type),
        addressToFr(params.assetIn),
        addressToFr(params.assetOut),
        toFr(params.fee),
        toFr(params.amountOutMin),
        toFr(params.recipient.ownerX),
        toFr(params.recipient.ownerY),
        toFr(params.recipient.claimerOwner),
      ]);

    case SwapType.ExactInput:
      return await Poseidon.hash([
        toFr(params.type),
        hashBytesToField(params.path),
        toFr(params.amountOutMin),
        toFr(params.recipient.ownerX),
        toFr(params.recipient.ownerY),
        toFr(params.recipient.claimerOwner),
      ]);

    case SwapType.ExactOutputSingle:
      return await Poseidon.hash([
        toFr(params.type),
        addressToFr(params.assetIn),
        addressToFr(params.assetOut),
        toFr(params.fee),
        toFr(params.amountOut),
        toFr(params.amountInMaximum),
        toFr(params.recipient.ownerX),
        toFr(params.recipient.ownerY),
        toFr(params.recipient.claimerOwner),
      ]);

    case SwapType.ExactOutput:
      return await Poseidon.hash([
        toFr(params.type),
        hashBytesToField(params.path),
        toFr(params.amountOut),
        toFr(params.amountInMaximum),
        toFr(params.recipient.ownerX),
        toFr(params.recipient.ownerY),
        toFr(params.recipient.claimerOwner),
      ]);

    default:
      throw new Error(`Unknown SwapType: ${(params as { type: number }).type}`);
  }
}
