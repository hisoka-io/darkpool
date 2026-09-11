import { Fr } from "@hisoka/wallets";
import {
  AbiCoder,
  concat,
  getAddress,
  getBytes,
  hexlify,
  isHexString,
  keccak256,
  toUtf8Bytes,
} from "ethers";
import { AdaptorError } from "../errors.js";

const WITHDRAW_PUBLIC_INPUTS = 17;
const ZERO_BYTES32 = `0x${"00".repeat(32)}`;

export interface HowlWithdrawProof {
  readonly proof: Uint8Array | string;
  readonly publicInputs: readonly string[];
}

export interface BuiltHowlPayment {
  readonly paymentId: string;
  readonly feeAsset: string;
  readonly amount: bigint;
  readonly intentHash: Fr;
  readonly paymentData: string;
}

export function howlPaymentIntent(executionId: string): Fr {
  if (!isHexString(executionId, 32)) {
    throw new AdaptorError(
      "Howl payment execution ID must be exactly 32 bytes",
    );
  }
  const digest = keccak256(
    concat([toUtf8Bytes("hisoka.nox.howl-payment.v1"), getBytes(executionId)]),
  );
  return new Fr(BigInt(digest) % Fr.MODULUS);
}

export function buildHowlPayment(
  executionId: string,
  adapter: string,
  withdrawProof: HowlWithdrawProof,
): BuiltHowlPayment {
  if (withdrawProof.publicInputs.length !== WITHDRAW_PUBLIC_INPUTS) {
    throw new AdaptorError(
      `Howl payment withdraw requires ${WITHDRAW_PUBLIC_INPUTS} public inputs, got ${withdrawProof.publicInputs.length}`,
    );
  }
  const adapterAddress = getAddress(adapter);
  const inputs = withdrawProof.publicInputs.map((input, index) => {
    if (!isHexString(input, 32)) {
      throw new AdaptorError(
        `Howl payment public input ${index} must be exactly 32 bytes`,
      );
    }
    return input;
  });
  const expectedIntent = howlPaymentIntent(executionId);
  if (BigInt(inputs[2]!) !== expectedIntent.toBigInt()) {
    throw new AdaptorError(
      "Howl payment withdraw intent does not bind the execution ID",
    );
  }
  if (BigInt(inputs[1]!) !== BigInt(adapterAddress)) {
    throw new AdaptorError(
      "Howl payment withdraw recipient is not the payment adapter",
    );
  }
  const paymentId = inputs[5]!;
  if (paymentId.toLowerCase() === ZERO_BYTES32) {
    throw new AdaptorError("Howl payment withdraw has a zero payment ID");
  }
  const amount = BigInt(inputs[0]!);
  if (amount === 0n) {
    throw new AdaptorError("Howl payment withdraw amount must be positive");
  }
  const assetValue = BigInt(inputs[7]!);
  if (assetValue > (1n << 160n) - 1n) {
    throw new AdaptorError("Howl payment fee asset exceeds the address width");
  }
  const feeAsset = getAddress(`0x${assetValue.toString(16).padStart(40, "0")}`);
  const proof = hexlify(withdrawProof.proof);
  return {
    paymentId,
    feeAsset,
    amount,
    intentHash: expectedIntent,
    paymentData: AbiCoder.defaultAbiCoder().encode(
      ["bytes", "bytes32[]"],
      [proof, inputs],
    ),
  };
}
