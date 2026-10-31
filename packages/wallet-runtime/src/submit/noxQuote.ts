import type { Fr } from "@aztec/foundation/fields";
import { howlPaymentIntent } from "@hisoka/adaptors";
import { getAddress, keccak256, TypedDataEncoder, hexlify } from "ethers";
import { WalletRuntimeError } from "../errors.js";

/**
 * A Nox execution quote as `NoxEntryPoint` hashes it. Field order and types are the contract's
 * `QUOTE_TYPEHASH` string; `executionId` is its EIP-712 digest under the `NoxEntryPoint` version 1 domain.
 */
export interface ExecutionQuote {
  readonly quoteVersion: number;
  readonly chainId: bigint;
  readonly entryPoint: string;
  readonly exitAddress: string;
  readonly clientIntentId: string;
  readonly paymentAdapter: string;
  readonly paymentId: string;
  readonly feeAsset: string;
  readonly exitFee: bigint;
  readonly networkFee: bigint;
  readonly paymentGasLimit: bigint;
  readonly actionTarget: string;
  readonly actionCalldataHash: string;
  readonly actionGasLimit: bigint;
  readonly trackedAssetsHash: string;
  readonly maximumTransactionGas: bigint;
  readonly maximumFeePerGas: bigint;
  readonly returnDataLimit: bigint;
  readonly validAfterUnix: bigint;
  readonly validUntilUnix: bigint;
  readonly quoteNonce: bigint;
}

export const QUOTE_VERSION = 1;

export const EXECUTION_QUOTE_TYPES = {
  ExecutionQuote: [
    { name: "quoteVersion", type: "uint8" },
    { name: "chainId", type: "uint256" },
    { name: "entryPoint", type: "address" },
    { name: "exitAddress", type: "address" },
    { name: "clientIntentId", type: "bytes32" },
    { name: "paymentAdapter", type: "address" },
    { name: "paymentId", type: "bytes32" },
    { name: "feeAsset", type: "address" },
    { name: "exitFee", type: "uint256" },
    { name: "networkFee", type: "uint256" },
    { name: "paymentGasLimit", type: "uint256" },
    { name: "actionTarget", type: "address" },
    { name: "actionCalldataHash", type: "bytes32" },
    { name: "actionGasLimit", type: "uint256" },
    { name: "trackedAssetsHash", type: "bytes32" },
    { name: "maximumTransactionGas", type: "uint256" },
    { name: "maximumFeePerGas", type: "uint256" },
    { name: "returnDataLimit", type: "uint256" },
    { name: "validAfterUnix", type: "uint64" },
    { name: "validUntilUnix", type: "uint64" },
    { name: "quoteNonce", type: "uint256" },
  ],
};

/** The quote's `executionId`: what the fee withdraw's intent commits to. */
export function executionIdOf(quote: ExecutionQuote): string {
  return TypedDataEncoder.hash(
    {
      name: "NoxEntryPoint",
      version: "1",
      chainId: quote.chainId,
      verifyingContract: quote.entryPoint,
    },
    EXECUTION_QUOTE_TYPES,
    quote,
  );
}

/** What the group agreed to pay for, fixed before any signing round starts. */
export interface ApprovedFeeSpend {
  readonly chainId: bigint;
  readonly entryPoint: string;
  /** The `HowlPaymentAdapter` instance built on `withdrawMultisig`. */
  readonly paymentAdapter: string;
  /** The fee note's nullifier: the quote's `paymentId`. */
  readonly feeNoteNullifier: string;
  readonly feeAsset: string;
  /** Ceiling on `exitFee + networkFee`. */
  readonly maxTotalFee: bigint;
  /** The paid action the group approved. */
  readonly action: { readonly target: string; readonly data: Uint8Array };
}

/** The fields of the multisig withdraw message a signer is asked to sign. */
export interface FeeWithdrawMessage {
  /** `public_out`: what leaves the fee note. */
  readonly value: bigint;
  readonly recipient: string;
  readonly intentHash: Fr;
}

function refuse(field: string, expected: string, actual: string): never {
  throw new WalletRuntimeError(
    "QUOTE_REJECTED",
    `the fee quote's ${field} is ${actual}; the group approved ${expected}. Do not sign`,
    { field, expected, actual },
  );
}

const sameAddress = (a: string, b: string): boolean =>
  getAddress(a) === getAddress(b);

/**
 * The check every FROST signer runs before contributing a share to a multisig fee withdraw.
 *
 * `msg_withdraw` binds the recipient and an intent that is a hash of the quote, so a signer that signs it
 * without recomputing that hash cannot tell where the fee goes or what action it pays for. Each signer
 * therefore takes the quote preimage and the action, recomputes `executionId` and the payment intent, and
 * checks the fee, the adapter, the payment id, the asset and the action against what the group approved.
 * Returns the recomputed `executionId` and intent; throws `QUOTE_REJECTED` naming the first mismatch.
 */
export function verifyFeeQuoteForSigning(
  quote: ExecutionQuote,
  approved: ApprovedFeeSpend,
  message: FeeWithdrawMessage,
): { readonly executionId: string; readonly intentHash: Fr } {
  if (quote.quoteVersion !== QUOTE_VERSION) {
    refuse("quoteVersion", String(QUOTE_VERSION), String(quote.quoteVersion));
  }
  if (quote.chainId !== approved.chainId) {
    refuse("chainId", String(approved.chainId), String(quote.chainId));
  }
  if (!sameAddress(quote.entryPoint, approved.entryPoint)) {
    refuse("entryPoint", approved.entryPoint, quote.entryPoint);
  }
  if (!sameAddress(quote.paymentAdapter, approved.paymentAdapter)) {
    refuse("paymentAdapter", approved.paymentAdapter, quote.paymentAdapter);
  }
  if (
    quote.paymentId.toLowerCase() !== approved.feeNoteNullifier.toLowerCase()
  ) {
    refuse("paymentId", approved.feeNoteNullifier, quote.paymentId);
  }
  if (!sameAddress(quote.feeAsset, approved.feeAsset)) {
    refuse("feeAsset", approved.feeAsset, quote.feeAsset);
  }
  if (!sameAddress(quote.actionTarget, approved.action.target)) {
    refuse("actionTarget", approved.action.target, quote.actionTarget);
  }
  const calldataHash = keccak256(hexlify(approved.action.data));
  if (quote.actionCalldataHash.toLowerCase() !== calldataHash) {
    refuse("actionCalldataHash", calldataHash, quote.actionCalldataHash);
  }
  const total = quote.exitFee + quote.networkFee;
  if (total > approved.maxTotalFee) {
    refuse(
      "exitFee + networkFee",
      `at most ${approved.maxTotalFee}`,
      String(total),
    );
  }
  if (message.value !== total) {
    refuse(
      "withdraw value",
      `exitFee + networkFee = ${total}`,
      String(message.value),
    );
  }
  if (!sameAddress(message.recipient, approved.paymentAdapter)) {
    refuse("withdraw recipient", approved.paymentAdapter, message.recipient);
  }
  const executionId = executionIdOf(quote);
  const intentHash = howlPaymentIntent(executionId);
  if (!message.intentHash.equals(intentHash)) {
    refuse(
      "withdraw intent",
      intentHash.toString(),
      message.intentHash.toString(),
    );
  }
  return { executionId, intentHash };
}
