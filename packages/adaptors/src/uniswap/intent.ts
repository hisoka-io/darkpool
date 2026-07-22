import { Poseidon, addressToFr, toFr, Fr } from "@hisoka/wallets";
import { UniswapSwapParams, SwapType } from "./types.js";
import { keccak256 } from "ethers";
import { AdaptorError } from "../errors.js";

function hashBytesToField(data: string): Fr {
  const hashHex = keccak256(data);
  const reduced = BigInt(hashHex) % Fr.MODULUS;
  return new Fr(reduced);
}

async function hashSwapParams(params: UniswapSwapParams): Promise<Fr> {
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
        toFr(params.salt),
      ]);

    case SwapType.ExactInput:
      return await Poseidon.hash([
        toFr(params.type),
        hashBytesToField(params.path),
        toFr(params.amountOutMin),
        toFr(params.recipient.ownerX),
        toFr(params.recipient.ownerY),
        toFr(params.salt),
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
        toFr(params.salt),
      ]);

    case SwapType.ExactOutput:
      return await Poseidon.hash([
        toFr(params.type),
        hashBytesToField(params.path),
        toFr(params.amountOut),
        toFr(params.amountInMaximum),
        toFr(params.recipient.ownerX),
        toFr(params.recipient.ownerY),
        toFr(params.salt),
      ]);

    default:
      throw new AdaptorError(
        `Unknown SwapType: ${(params as { type: number }).type}`,
      );
  }
}

export async function hashUniswapIntent(
  params: UniswapSwapParams,
  deadline: bigint,
): Promise<Fr> {
  const base = await hashSwapParams(params);
  return await Poseidon.hash([base, toFr(deadline)]);
}
