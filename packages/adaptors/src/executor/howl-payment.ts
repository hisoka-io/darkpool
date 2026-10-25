import { Fr } from "@hisoka/wallets";
import {
  AbiCoder,
  concat,
  dataLength,
  dataSlice,
  getAddress,
  getBytes,
  hexlify,
  id,
  isHexString,
  keccak256,
  toUtf8Bytes,
} from "ethers";
import { AdaptorError } from "../errors.js";

const WITHDRAW_PUBLIC_INPUTS = 17;
const NULLIFIER_INPUT = 5;
/** Honk ZK proof of the withdraw circuit: (82 + 12 * LOG_N) words at LOG_N = 15, the size its verifier accepts. */
const WITHDRAW_PROOF_BYTES = (82 + 12 * 15) * 32;
const ZERO_BYTES32 = `0x${"00".repeat(32)}`;
const BASIS_POINTS = 10_000n;

/** Entrypoints whose first two arguments are a withdraw proof and its public inputs. */
const WITHDRAW_CARRYING_SELECTORS: readonly string[] = [
  "withdraw(bytes,bytes32[])",
  "execute(bytes,bytes32[],(address,bytes,uint256,bool,address,uint256,uint256,uint256)[],uint256,address[],address[])",
].map((signature) => dataSlice(id(signature), 0, 4));

/** A withdraw inserts one leaf; each of the 32 tree levels costs at most one Poseidon2 hash_3. */
const TREE_ALLOWANCE_GAS = 32n * 24_000n;
/**
 * `HowlPaymentAdapter.pay` and `DarkPool.withdraw` frames on the deployed pool, rounded up from the highest
 * traced on Arbitrum Sepolia (2026-10-13, leaves 28 to 31): pay 1,027,697, withdraw 879,320.
 */
const PAY_FRAME_GAS = 1_030_000n;
const WITHDRAW_FRAME_GAS = 880_000n;
/** A payment that runs out of gas reverts uncharged; an action that runs out of gas is charged. */
const PAYMENT_MARGIN_BPS = 1_000n;
const ACTION_MARGIN_BPS = 2_000n;

function withMargin(gas: bigint, marginBps: bigint): bigint {
  return (gas * (BASIS_POINTS + marginBps) + BASIS_POINTS - 1n) / BASIS_POINTS;
}

/** `paymentGasLimit` for a Howl fee withdraw, valid at every leaf index of the pool tree. */
export const HOWL_PAYMENT_GAS_LIMIT = withMargin(
  PAY_FRAME_GAS + TREE_ALLOWANCE_GAS,
  PAYMENT_MARGIN_BPS,
);
/** `actionGasLimit` for `DarkPool.withdraw` as the paid action, valid at every leaf index of the pool tree. */
export const HOWL_WITHDRAW_ACTION_GAS_LIMIT = withMargin(
  WITHDRAW_FRAME_GAS + TREE_ALLOWANCE_GAS,
  ACTION_MARGIN_BPS,
);

/** Bytes of the ABI-encoded `(bytes proof, bytes32[] publicInputs)` of a fee withdraw. */
export const HOWL_PAYMENT_DATA_LENGTH =
  4 * 32 + WITHDRAW_PROOF_BYTES + WITHDRAW_PUBLIC_INPUTS * 32;

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

/** Structurally a nox-client `PaidPaymentSource`: one fee note pays one paid execution. */
export interface HowlPaymentSource {
  readonly adapter: string;
  readonly feeAsset: string;
  readonly paymentId: Uint8Array;
  readonly gasLimit: bigint;
  readonly paymentDataLength: number;
  checkAction(action: { readonly data: Uint8Array }): void;
  buildPaymentData(args: {
    readonly executionId: Uint8Array;
    readonly amount: bigint;
    readonly feeAsset: string;
  }): Promise<Uint8Array>;
}

export interface HowlPaymentSourceArgs {
  readonly adapter: string;
  readonly feeAsset: string;
  readonly feeNoteNullifier: string;
  readonly feeNoteValue: bigint;
  /** Proves a withdraw of `amount` from the fee note to `recipient`, bound to `intentHash`. */
  readonly proveFeeWithdraw: (
    amount: bigint,
    recipient: string,
    intentHash: Fr,
  ) => Promise<HowlWithdrawProof>;
  readonly gasLimit?: bigint;
}

export function howlPaymentSource(
  args: HowlPaymentSourceArgs,
): HowlPaymentSource {
  const adapter = getAddress(args.adapter);
  const feeAsset = getAddress(args.feeAsset);
  if (
    !isHexString(args.feeNoteNullifier, 32) ||
    args.feeNoteNullifier.toLowerCase() === ZERO_BYTES32
  ) {
    throw new AdaptorError(
      "Howl fee note nullifier must be a non-zero 32-byte value",
    );
  }
  const feeNoteNullifier = args.feeNoteNullifier.toLowerCase();
  if (args.feeNoteValue <= 0n) {
    throw new AdaptorError("Howl fee note value must be positive");
  }
  const gasLimit = args.gasLimit ?? HOWL_PAYMENT_GAS_LIMIT;
  if (gasLimit <= 0n) {
    throw new AdaptorError("Howl payment gas limit must be positive");
  }

  return {
    adapter,
    feeAsset,
    paymentId: getBytes(feeNoteNullifier),
    gasLimit,
    paymentDataLength: HOWL_PAYMENT_DATA_LENGTH,
    checkAction(action) {
      const data = hexlify(action.data);
      if (
        dataLength(data) < 4 ||
        !WITHDRAW_CARRYING_SELECTORS.includes(dataSlice(data, 0, 4))
      ) {
        return;
      }
      let publicInputs: readonly string[];
      try {
        [, publicInputs] = AbiCoder.defaultAbiCoder().decode(
          ["bytes", "bytes32[]"],
          dataSlice(data, 4),
        ) as unknown as [string, string[]];
      } catch {
        throw new AdaptorError(
          "Paid action carries a withdraw whose public inputs do not decode",
        );
      }
      if (publicInputs.length !== WITHDRAW_PUBLIC_INPUTS) {
        throw new AdaptorError(
          `Paid action withdraw requires ${WITHDRAW_PUBLIC_INPUTS} public inputs, got ${publicInputs.length}`,
        );
      }
      if (publicInputs[NULLIFIER_INPUT]!.toLowerCase() === feeNoteNullifier) {
        throw new AdaptorError(
          "Paid action spends the fee note: the fee withdraw runs first, so the action would fail after the fee is paid",
        );
      }
    },
    async buildPaymentData({ executionId, amount, feeAsset: quotedAsset }) {
      if (getAddress(quotedAsset) !== feeAsset) {
        throw new AdaptorError(
          `Quoted fee asset ${quotedAsset} is not the fee note asset ${feeAsset}`,
        );
      }
      if (amount > args.feeNoteValue) {
        throw new AdaptorError(
          `Quoted fee ${amount} exceeds the fee note value ${args.feeNoteValue}`,
        );
      }
      const execution = hexlify(executionId);
      const proof = await args.proveFeeWithdraw(
        amount,
        adapter,
        howlPaymentIntent(execution),
      );
      const payment = buildHowlPayment(execution, adapter, proof);
      if (payment.paymentId.toLowerCase() !== feeNoteNullifier) {
        throw new AdaptorError(
          "Fee withdraw proof spends a different note than the quoted payment ID",
        );
      }
      if (payment.amount !== amount) {
        throw new AdaptorError(
          `Fee withdraw proof pays ${payment.amount}, quoted fee is ${amount}`,
        );
      }
      if (payment.feeAsset !== feeAsset) {
        throw new AdaptorError(
          `Fee withdraw proof pays in ${payment.feeAsset}, quoted fee asset is ${feeAsset}`,
        );
      }
      return getBytes(payment.paymentData);
    },
  };
}
