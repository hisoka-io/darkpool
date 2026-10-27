import { Fr } from "@hisoka/wallets";
import {
  AbiCoder,
  concat,
  type ContractRunner,
  dataLength,
  dataSlice,
  FunctionFragment,
  getAddress,
  getBytes,
  hexlify,
  id,
  isHexString,
  keccak256,
  toUtf8Bytes,
} from "ethers";
import { AdaptorError } from "../errors.js";
import { BUNDLE_EXECUTE_FRAGMENT } from "./abi.js";

const WITHDRAW_PUBLIC_INPUTS = 17;
const ZERO_BYTES32 = `0x${"00".repeat(32)}`;
const BASIS_POINTS = 10_000n;
const MULTISIG_FLAG_CALL = dataSlice(id("MULTISIG()"), 0, 4);

/** Public-input count and nullifier positions of one spend entrypoint, as `DarkPool` checks and spends them. */
interface SpendLayout {
  readonly publicInputs: number;
  readonly nullifierInputs: readonly number[];
}

const WITHDRAW_SPEND: SpendLayout = {
  publicInputs: WITHDRAW_PUBLIC_INPUTS,
  nullifierInputs: [5],
};
const TRANSFER_SPEND: SpendLayout = { publicInputs: 24, nullifierInputs: [2] };
const SPLIT_SPEND: SpendLayout = { publicInputs: 22, nullifierInputs: [2] };
const JOIN_SPEND: SpendLayout = { publicInputs: 14, nullifierInputs: [2, 3] };
/**
 * `DarkPool.settle` reads a module's vector as `[compliance x, y, timestamp, nullifier_1..k, root, outputs...]`;
 * Kage registers k = 2 nullifiers and 4 outputs of 9 words, no module words.
 */
const KAGE_SETTLE_SPEND: SpendLayout = {
  publicInputs: 3 + 2 + 1 + 4 * 9,
  nullifierInputs: [3, 4],
};

const BUNDLE_EXECUTE_SIGNATURE = BUNDLE_EXECUTE_FRAGMENT.format("sighash");

interface SpendEntrypoint extends SpendLayout {
  readonly signature: string;
  readonly fragment: FunctionFragment;
  /** Argument position of the spend's public inputs. */
  readonly publicInputsArg: number;
}

/**
 * Every entrypoint that carries a spend proof and its public inputs: the `DarkPool` spends, the adaptors that
 * forward a withdraw, and `KageSettlement.settleSwap`. `BundleExecutor.execute` is also searched through its
 * bound calls.
 */
const SPEND_ENTRYPOINTS: ReadonlyMap<string, SpendEntrypoint> = new Map(
  (
    [
      ["withdraw(bytes,bytes32[])", WITHDRAW_SPEND, 1],
      ["withdrawMultisig(bytes,bytes32[])", WITHDRAW_SPEND, 1],
      ["privateTransfer(bytes,bytes32[])", TRANSFER_SPEND, 1],
      ["transferMultisig(bytes,bytes32[])", TRANSFER_SPEND, 1],
      ["split(bytes,bytes32[])", SPLIT_SPEND, 1],
      ["splitMultisig(bytes,bytes32[])", SPLIT_SPEND, 1],
      ["join(bytes,bytes32[])", JOIN_SPEND, 1],
      ["joinMultisig(bytes,bytes32[])", JOIN_SPEND, 1],
      ["executeSwap(bytes,bytes32[],uint8,bytes,uint256)", WITHDRAW_SPEND, 1],
      [
        "settleSwap(uint256,uint256,bytes,bytes,bytes32[])",
        KAGE_SETTLE_SPEND,
        4,
      ],
      [BUNDLE_EXECUTE_SIGNATURE, WITHDRAW_SPEND, 1],
    ] as const
  ).map(([signature, layout, publicInputsArg]) => [
    dataSlice(id(signature), 0, 4),
    {
      signature,
      fragment: FunctionFragment.from(`function ${signature}`),
      publicInputsArg,
      ...layout,
    },
  ]),
);

/** Bundles nested inside bound calls are searched to this depth; a deeper action is refused, not passed. */
const MAX_BUNDLE_DEPTH = 4;

/** A withdraw inserts one leaf; each of the 32 tree levels costs at most one Poseidon2 hash_3. */
const TREE_ALLOWANCE_GAS = 32n * 24_000n;
/** A payment that runs out of gas reverts uncharged; an action that runs out of gas is charged. */
const PAYMENT_MARGIN_BPS = 1_000n;
const ACTION_MARGIN_BPS = 2_000n;

/**
 * Size and gas of one withdraw circuit as its deployed verifier accepts it. Re-measure whenever that
 * verifier is replaced: a larger proof fails the payment-data bound, and a costlier verifier makes a paid
 * withdraw action run out of gas while its fee is still charged.
 */
export interface HowlWithdrawProfile {
  /** Exact byte length of one proof accepted by the deployed verifier. */
  readonly proofBytes: number;
  /** Highest traced `HowlPaymentAdapter.pay` frame; the tree allowance is added on top. */
  readonly payFrameGas: bigint;
  /** Highest traced DarkPool withdraw frame as a paid action; the tree allowance is added on top. */
  readonly withdrawFrameGas: bigint;
}

/**
 * `withdraw`: proof length read from the deployed `WithdrawVerifier` (LOG_N 15); frames traced on the
 * deployed pool.
 */
export const HOWL_WITHDRAW_PROFILE: HowlWithdrawProfile = {
  proofBytes: 8_384,
  payFrameGas: 1_010_000n,
  withdrawFrameGas: 827_000n,
};

/**
 * `withdrawMultisig`: proof length read from the deployed `WithdrawMultisigVerifier` (LOG_N 15). Its pay and
 * action frames equal the standard ones within proof-dependent noise (tens of gas either way, since proof bytes
 * differ per proof), far inside the headroom of the standard traced frames, so those frames bound it.
 */
export const HOWL_WITHDRAW_MULTISIG_PROFILE: HowlWithdrawProfile = {
  proofBytes: 8_384,
  payFrameGas: 1_010_000n,
  withdrawFrameGas: 827_000n,
};

function withMargin(gas: bigint, marginBps: bigint): bigint {
  return (gas * (BASIS_POINTS + marginBps) + BASIS_POINTS - 1n) / BASIS_POINTS;
}

/** `paymentGasLimit` for a Howl fee withdraw, valid at every leaf index of the pool tree. */
export function howlPaymentGasLimit(profile: HowlWithdrawProfile): bigint {
  if (profile.payFrameGas <= 0n) {
    throw new AdaptorError(
      `Howl pay frame gas must be positive, got ${profile.payFrameGas}`,
    );
  }
  return withMargin(
    profile.payFrameGas + TREE_ALLOWANCE_GAS,
    PAYMENT_MARGIN_BPS,
  );
}

/** `actionGasLimit` for a DarkPool withdraw as the paid action, valid at every leaf index of the pool tree. */
export function howlWithdrawActionGasLimit(
  profile: HowlWithdrawProfile,
): bigint {
  if (profile.withdrawFrameGas <= 0n) {
    throw new AdaptorError(
      `Howl withdraw frame gas must be positive, got ${profile.withdrawFrameGas}`,
    );
  }
  return withMargin(
    profile.withdrawFrameGas + TREE_ALLOWANCE_GAS,
    ACTION_MARGIN_BPS,
  );
}

/** Bytes of the ABI-encoded `(bytes proof, bytes32[] publicInputs)` carrying a proof of `proofBytes`. */
export function howlPaymentDataLength(proofBytes: number): number {
  if (!Number.isSafeInteger(proofBytes) || proofBytes <= 0) {
    throw new AdaptorError(
      `Howl withdraw proof size must be a positive integer, got ${proofBytes}`,
    );
  }
  const paddedProof = Math.ceil(proofBytes / 32) * 32;
  return 4 * 32 + paddedProof + WITHDRAW_PUBLIC_INPUTS * 32;
}

export const HOWL_PAYMENT_GAS_LIMIT = howlPaymentGasLimit(
  HOWL_WITHDRAW_PROFILE,
);
export const HOWL_WITHDRAW_ACTION_GAS_LIMIT = howlWithdrawActionGasLimit(
  HOWL_WITHDRAW_PROFILE,
);
export const HOWL_PAYMENT_DATA_LENGTH = howlPaymentDataLength(
  HOWL_WITHDRAW_PROFILE.proofBytes,
);

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
  /** Reads the adapter's `MULTISIG()` flag; the source refuses an instance of the other kind before proving. */
  readonly runner: ContractRunner;
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
  /** Overrides the size and gas profile of the deployed withdraw verifier. */
  readonly profile?: HowlWithdrawProfile;
}

/** Pays from a standard note through the `HowlPaymentAdapter` instance built on `withdraw`. */
export function howlPaymentSource(
  args: HowlPaymentSourceArgs,
): HowlPaymentSource {
  return createHowlPaymentSource(args, HOWL_WITHDRAW_PROFILE, false);
}

/**
 * Pays from a FROST multisig note through the `HowlPaymentAdapter` instance built on `withdrawMultisig`.
 * `proveFeeWithdraw` runs the quorum signing over `msgWithdraw` (which signs `recipient` and `intentHash`)
 * and proves `withdraw_multisig`. `adapter` must be the instance whose `MULTISIG()` is true; the standard
 * source requires it false. Each signer must run `verifyFeeQuoteForSigning` from `@hisoka/wallet-runtime`
 * before contributing a share: the signed intent is a hash of the quote, so only a signer that recomputes it
 * from the quote preimage knows which fee and action the share approves.
 */
export function howlMultisigPaymentSource(
  args: HowlPaymentSourceArgs,
): HowlPaymentSource {
  return createHowlPaymentSource(args, HOWL_WITHDRAW_MULTISIG_PROFILE, true);
}

type EthCall = NonNullable<ContractRunner["call"]>;

async function readAdapterMultisig(
  call: EthCall,
  adapter: string,
): Promise<boolean> {
  let word: string;
  try {
    word = await call({ to: adapter, data: MULTISIG_FLAG_CALL });
  } catch (cause) {
    const reason = cause instanceof Error ? cause.message : String(cause);
    throw new AdaptorError(
      `Reading MULTISIG() from payment adapter ${adapter} failed: ${reason}`,
    );
  }
  if (!isHexString(word, 32) || BigInt(word) > 1n) {
    throw new AdaptorError(
      `Payment adapter ${adapter} answered MULTISIG() with ${isHexString(word) ? `${dataLength(word)} bytes` : "a non-hex value"} that is not a boolean word: it is not a HowlPaymentAdapter`,
    );
  }
  return BigInt(word) === 1n;
}

function adapterKind(multisig: boolean): string {
  return multisig ? "withdrawMultisig" : "withdraw";
}

function assertActionSparesNote(
  data: string,
  feeNoteNullifier: string,
  depth: number,
): void {
  if (dataLength(data) < 4) return;
  const entrypoint = SPEND_ENTRYPOINTS.get(dataSlice(data, 0, 4));
  if (entrypoint === undefined) return;
  const args = dataSlice(data, 4);
  let publicInputs: readonly string[];
  let nestedCalls: readonly string[] = [];
  try {
    if (entrypoint.signature === BUNDLE_EXECUTE_SIGNATURE) {
      const decoded = AbiCoder.defaultAbiCoder().decode(
        BUNDLE_EXECUTE_FRAGMENT.inputs,
        args,
      );
      publicInputs = decoded[1] as string[];
      nestedCalls = (decoded[2] as unknown as readonly { data: string }[]).map(
        (call) => call.data,
      );
    } else {
      const decoded = AbiCoder.defaultAbiCoder().decode(
        entrypoint.fragment.inputs,
        args,
      );
      publicInputs = decoded[entrypoint.publicInputsArg] as string[];
    }
  } catch {
    throw new AdaptorError(
      `Paid action carries a ${entrypoint.signature} spend whose public inputs do not decode`,
    );
  }
  if (publicInputs.length !== entrypoint.publicInputs) {
    throw new AdaptorError(
      `Paid action ${entrypoint.signature} requires ${entrypoint.publicInputs} public inputs, got ${publicInputs.length}`,
    );
  }
  for (const index of entrypoint.nullifierInputs) {
    if (publicInputs[index]!.toLowerCase() === feeNoteNullifier) {
      throw new AdaptorError(
        `Paid action spends the fee note through ${entrypoint.signature} (public input ${index}): the fee withdraw runs first, so the action would fail after the fee is paid`,
      );
    }
  }
  if (nestedCalls.length === 0) return;
  if (depth >= MAX_BUNDLE_DEPTH) {
    throw new AdaptorError(
      `Paid action nests bundles deeper than ${MAX_BUNDLE_DEPTH}; refused because its spends cannot all be checked against the fee note`,
    );
  }
  for (const call of nestedCalls) {
    assertActionSparesNote(call, feeNoteNullifier, depth + 1);
  }
}

function createHowlPaymentSource(
  args: HowlPaymentSourceArgs,
  defaultProfile: HowlWithdrawProfile,
  multisig: boolean,
): HowlPaymentSource {
  const adapter = getAddress(args.adapter);
  const { runner } = args;
  if (typeof runner.call !== "function") {
    throw new AdaptorError(
      `Howl payment source needs a runner that can eth_call to read MULTISIG() from adapter ${adapter}`,
    );
  }
  const ethCall: EthCall = runner.call.bind(runner);
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
  const profile = args.profile ?? defaultProfile;
  const paymentDataLength = howlPaymentDataLength(profile.proofBytes);
  const gasLimit = args.gasLimit ?? howlPaymentGasLimit(profile);
  if (gasLimit <= 0n) {
    throw new AdaptorError("Howl payment gas limit must be positive");
  }
  let adapterKindChecked = false;

  return {
    adapter,
    feeAsset,
    paymentId: getBytes(feeNoteNullifier),
    gasLimit,
    paymentDataLength,
    checkAction(action) {
      assertActionSparesNote(hexlify(action.data), feeNoteNullifier, 0);
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
      if (!adapterKindChecked) {
        const adapterIsMultisig = await readAdapterMultisig(ethCall, adapter);
        if (adapterIsMultisig !== multisig) {
          throw new AdaptorError(
            `Payment adapter ${adapter} pulls fees through ${adapterKind(adapterIsMultisig)} (MULTISIG() is ${adapterIsMultisig}), but this fee note pays through ${adapterKind(multisig)}: use the instance whose MULTISIG() is ${multisig}`,
          );
        }
        adapterKindChecked = true;
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
      const paymentData = getBytes(payment.paymentData);
      if (paymentData.length > paymentDataLength) {
        throw new AdaptorError(
          `Fee withdraw payment data is ${paymentData.length} bytes, above the declared ${paymentDataLength}: the withdraw profile does not match the deployed verifier`,
        );
      }
      return paymentData;
    },
  };
}
