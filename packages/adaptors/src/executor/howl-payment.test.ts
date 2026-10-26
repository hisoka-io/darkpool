import { describe, expect, it } from "vitest";
import {
  AbiCoder,
  concat,
  getBytes,
  hexlify,
  Interface,
  keccak256,
  toUtf8Bytes,
} from "ethers";
import { Fr } from "@hisoka/wallets";
import { buildBundle, encodeBundleExecute } from "./bundle.js";
import {
  buildHowlPayment,
  HOWL_PAYMENT_DATA_LENGTH,
  HOWL_PAYMENT_GAS_LIMIT,
  HOWL_WITHDRAW_ACTION_GAS_LIMIT,
  HOWL_WITHDRAW_MULTISIG_PROFILE,
  HOWL_WITHDRAW_PROFILE,
  howlMultisigPaymentSource,
  howlPaymentDataLength,
  howlPaymentGasLimit,
  howlPaymentIntent,
  howlPaymentSource,
  howlWithdrawActionGasLimit,
  type HowlPaymentSourceArgs,
  type HowlWithdrawProof,
} from "./howl-payment.js";

const EXECUTION_ID =
  "0x1111111111111111111111111111111111111111111111111111111111111111";
const ADAPTER = "0x2222222222222222222222222222222222222222";
const ASSET = "0x3333333333333333333333333333333333333333";
const PAYMENT_ID =
  "0x4444444444444444444444444444444444444444444444444444444444444444";
const OTHER_NOTE =
  "0x5555555555555555555555555555555555555555555555555555555555555555";
const EXECUTOR = "0x6666666666666666666666666666666666666666";
const DARK_POOL = "0x7777777777777777777777777777777777777777";
const NOTE_VALUE = 100n;

function word(value: bigint | string): string {
  return `0x${BigInt(value).toString(16).padStart(64, "0")}`;
}

function withdrawProof(overrides: Record<number, string>): HowlWithdrawProof {
  const publicInputs = Array<string>(17).fill(word(0n));
  for (const [index, value] of Object.entries(overrides)) {
    publicInputs[Number(index)] = value;
  }
  return { proof: new Uint8Array([1, 2, 3]), publicInputs };
}

function feeProof(amount: bigint, recipient: string, intentHash: Fr) {
  return withdrawProof({
    0: word(amount),
    1: word(recipient),
    2: intentHash.toString(),
    5: PAYMENT_ID,
    7: word(ASSET),
  });
}

function source(
  prove: (
    amount: bigint,
    recipient: string,
    intentHash: Fr,
  ) => HowlWithdrawProof = feeProof,
) {
  return howlPaymentSource({
    adapter: ADAPTER,
    feeAsset: ASSET,
    feeNoteNullifier: PAYMENT_ID,
    feeNoteValue: NOTE_VALUE,
    proveFeeWithdraw: (amount, recipient, intentHash) =>
      Promise.resolve(prove(amount, recipient, intentHash)),
  });
}

const paymentRequest = {
  executionId: getBytes(EXECUTION_ID),
  amount: 40n,
  feeAsset: ASSET,
};

const withdrawIface = new Interface([
  "function withdraw(bytes proof, bytes32[] publicInputs)",
  "function withdrawMultisig(bytes proof, bytes32[] publicInputs)",
  "function deposit(bytes proof, bytes32[] publicInputs)",
]);

function bundleAction(nullifier: string): Uint8Array {
  const bundle = buildBundle(
    { chainId: 31337n, executor: EXECUTOR, darkPool: DARK_POOL },
    [],
    1893456000n,
    [ASSET],
    [],
  );
  return getBytes(
    encodeBundleExecute(
      bundle,
      withdrawProof({
        1: word(EXECUTOR),
        2: bundle.intentHash.toString(),
        5: nullifier,
      }),
    ),
  );
}

function withdrawAction(nullifier: string): Uint8Array {
  const proof = withdrawProof({ 5: nullifier });
  return getBytes(
    withdrawIface.encodeFunctionData("withdraw", [
      proof.proof,
      proof.publicInputs,
    ]),
  );
}

describe("Howl Nox payment builder", () => {
  it("matches the raw domain-label plus execution-id reduction", () => {
    const expected =
      BigInt(
        keccak256(
          concat([toUtf8Bytes("hisoka.nox.howl-payment.v1"), EXECUTION_ID]),
        ),
      ) % Fr.MODULUS;
    expect(howlPaymentIntent(EXECUTION_ID).toBigInt()).toBe(expected);
  });

  it("extracts and encodes only an exactly bound withdraw proof", () => {
    const inputs = Array<string>(17).fill(
      "0x0000000000000000000000000000000000000000000000000000000000000000",
    );
    inputs[0] = `0x${40n.toString(16).padStart(64, "0")}`;
    inputs[1] = `0x${BigInt(ADAPTER).toString(16).padStart(64, "0")}`;
    inputs[2] = howlPaymentIntent(EXECUTION_ID).toString();
    inputs[5] = PAYMENT_ID;
    inputs[7] = `0x${BigInt(ASSET).toString(16).padStart(64, "0")}`;
    const proof = new Uint8Array([1, 2, 3]);

    const built = buildHowlPayment(EXECUTION_ID, ADAPTER, {
      proof,
      publicInputs: inputs,
    });
    expect(built.paymentId).toBe(PAYMENT_ID);
    expect(built.feeAsset).toBe(ASSET);
    expect(built.amount).toBe(40n);
    expect(built.intentHash.toString()).toBe(inputs[2]);
    const decoded = AbiCoder.defaultAbiCoder().decode(
      ["bytes", "bytes32[]"],
      built.paymentData,
    );
    expect(getBytes(decoded[0])).toEqual(proof);
    expect([...decoded[1]]).toEqual(inputs);
  });

  it("rejects a proof bound to a different execution", () => {
    const inputs = Array<string>(17).fill(
      "0x0000000000000000000000000000000000000000000000000000000000000000",
    );
    inputs[0] = `0x${40n.toString(16).padStart(64, "0")}`;
    inputs[1] = `0x${BigInt(ADAPTER).toString(16).padStart(64, "0")}`;
    inputs[2] = `0x${1n.toString(16).padStart(64, "0")}`;
    inputs[5] = PAYMENT_ID;
    inputs[7] = `0x${BigInt(ASSET).toString(16).padStart(64, "0")}`;
    expect(() =>
      buildHowlPayment(EXECUTION_ID, ADAPTER, {
        proof: new Uint8Array([1]),
        publicInputs: inputs,
      }),
    ).toThrow(/intent/);
  });
});

describe("Howl Nox payment source", () => {
  it("exposes the fee note as the payment ID and the default payment gas limit", () => {
    const payment = source();
    expect(hexlify(payment.paymentId)).toBe(PAYMENT_ID);
    expect(payment.adapter).toBe(ADAPTER);
    expect(payment.feeAsset).toBe(ASSET);
    expect(payment.gasLimit).toBe(HOWL_PAYMENT_GAS_LIMIT);
  });

  it("pins the Howl gas limits", () => {
    expect(HOWL_PAYMENT_GAS_LIMIT).toBe(1_955_800n);
    expect(HOWL_WITHDRAW_ACTION_GAS_LIMIT).toBe(1_914_000n);
  });

  it("proves the quoted amount to the adapter under the execution intent", async () => {
    const calls: [bigint, string, string][] = [];
    const payment = source((amount, recipient, intentHash) => {
      calls.push([amount, recipient, intentHash.toString()]);
      return feeProof(amount, recipient, intentHash);
    });
    const paymentData = await payment.buildPaymentData(paymentRequest);
    expect(calls).toEqual([
      [40n, ADAPTER, howlPaymentIntent(EXECUTION_ID).toString()],
    ]);
    const decoded = AbiCoder.defaultAbiCoder().decode(
      ["bytes", "bytes32[]"],
      paymentData,
    );
    expect(decoded[1][0]).toBe(word(40n));
    expect(decoded[1][5]).toBe(PAYMENT_ID);
  });

  it("declares the encoded size of a fee withdraw with a full-size proof", async () => {
    const payment = source((amount, recipient, intentHash) => ({
      ...feeProof(amount, recipient, intentHash),
      proof: new Uint8Array(8_384).fill(7),
    }));
    expect(HOWL_PAYMENT_DATA_LENGTH).toBe(9_056);
    expect(payment.paymentDataLength).toBe(HOWL_PAYMENT_DATA_LENGTH);
    expect(await payment.buildPaymentData(paymentRequest)).toHaveLength(
      HOWL_PAYMENT_DATA_LENGTH,
    );
  });

  it("refuses a fee above the note value before proving", async () => {
    let proved = false;
    const payment = source((amount, recipient, intentHash) => {
      proved = true;
      return feeProof(amount, recipient, intentHash);
    });
    await expect(
      payment.buildPaymentData({ ...paymentRequest, amount: NOTE_VALUE + 1n }),
    ).rejects.toThrow(/exceeds the fee note value/);
    expect(proved).toBe(false);
  });

  it("refuses a quote in another fee asset before proving", async () => {
    await expect(
      source().buildPaymentData({ ...paymentRequest, feeAsset: ADAPTER }),
    ).rejects.toThrow(/is not the fee note asset/);
  });

  it("rejects a proof that spends a different note", async () => {
    const payment = source((amount, recipient, intentHash) => ({
      ...feeProof(amount, recipient, intentHash),
      publicInputs: feeProof(amount, recipient, intentHash).publicInputs.map(
        (input, index) => (index === 5 ? OTHER_NOTE : input),
      ),
    }));
    await expect(payment.buildPaymentData(paymentRequest)).rejects.toThrow(
      /different note/,
    );
  });

  it("rejects a proof for a different amount", async () => {
    const payment = source((amount, recipient, intentHash) =>
      feeProof(amount - 1n, recipient, intentHash),
    );
    await expect(payment.buildPaymentData(paymentRequest)).rejects.toThrow(
      /pays 39, quoted fee is 40/,
    );
  });

  it("rejects a proof in a different asset", async () => {
    const payment = source((amount, recipient, intentHash) => ({
      ...feeProof(amount, recipient, intentHash),
      publicInputs: feeProof(amount, recipient, intentHash).publicInputs.map(
        (input, index) => (index === 7 ? word(EXECUTOR) : input),
      ),
    }));
    await expect(payment.buildPaymentData(paymentRequest)).rejects.toThrow(
      /quoted fee asset/,
    );
  });

  it("rejects a malformed or zero fee note", () => {
    const build = (feeNoteNullifier: string, feeNoteValue: bigint) => () =>
      howlPaymentSource({
        adapter: ADAPTER,
        feeAsset: ASSET,
        feeNoteNullifier,
        feeNoteValue,
        proveFeeWithdraw: (amount, recipient, intentHash) =>
          Promise.resolve(feeProof(amount, recipient, intentHash)),
      });
    expect(build("0x1234", NOTE_VALUE)).toThrow(/nullifier/);
    expect(build(word(0n), NOTE_VALUE)).toThrow(/nullifier/);
    expect(build(PAYMENT_ID, 0n)).toThrow(/value must be positive/);
  });

  it("vetoes a withdraw action that spends the fee note", () => {
    const payment = source();
    expect(() =>
      payment.checkAction({ data: withdrawAction(PAYMENT_ID) }),
    ).toThrow(/spends the fee note/);
    expect(() =>
      payment.checkAction({
        data: withdrawAction(PAYMENT_ID.toUpperCase().replace("0X", "0x")),
      }),
    ).toThrow(/spends the fee note/);
  });

  it("vetoes a bundle whose withdraw spends the fee note", () => {
    expect(() =>
      source().checkAction({ data: bundleAction(PAYMENT_ID) }),
    ).toThrow(/spends the fee note/);
  });

  it("vetoes a withdraw-carrying action whose public inputs do not decode", () => {
    const payment = source();
    const selector = withdrawAction(OTHER_NOTE).slice(0, 4);
    expect(() => payment.checkAction({ data: selector })).toThrow(
      /do not decode/,
    );
    const short = withdrawIface.encodeFunctionData("withdraw", [
      "0x01",
      [PAYMENT_ID],
    ]);
    expect(() => payment.checkAction({ data: getBytes(short) })).toThrow(
      /requires 17 public inputs/,
    );
  });

  it("passes actions that spend another note or carry no withdraw", () => {
    const payment = source();
    payment.checkAction({ data: withdrawAction(OTHER_NOTE) });
    payment.checkAction({ data: bundleAction(OTHER_NOTE) });
    payment.checkAction({ data: new Uint8Array() });
    payment.checkAction({ data: new Uint8Array([0xde, 0xad]) });
    const proof = withdrawProof({ 5: PAYMENT_ID });
    payment.checkAction({
      data: getBytes(
        withdrawIface.encodeFunctionData("deposit", [
          proof.proof,
          proof.publicInputs,
        ]),
      ),
    });
  });
});

describe("Howl withdraw profiles", () => {
  it("derives the payment data bound from the proof size", () => {
    expect(howlPaymentDataLength(HOWL_WITHDRAW_PROFILE.proofBytes)).toBe(
      HOWL_PAYMENT_DATA_LENGTH,
    );
    expect(howlPaymentDataLength(928)).toBe(4 * 32 + 928 + 17 * 32);
    expect(howlPaymentDataLength(930)).toBe(4 * 32 + 960 + 17 * 32);
    expect(() => howlPaymentDataLength(0)).toThrow(/positive integer/);
    expect(() => howlPaymentDataLength(1.5)).toThrow(/positive integer/);
  });

  it("derives the gas limits from the frame gas of a profile", () => {
    expect(howlPaymentGasLimit(HOWL_WITHDRAW_PROFILE)).toBe(
      HOWL_PAYMENT_GAS_LIMIT,
    );
    expect(howlWithdrawActionGasLimit(HOWL_WITHDRAW_PROFILE)).toBe(
      HOWL_WITHDRAW_ACTION_GAS_LIMIT,
    );
    const costlier = {
      ...HOWL_WITHDRAW_PROFILE,
      payFrameGas: HOWL_WITHDRAW_PROFILE.payFrameGas + 100_000n,
      withdrawFrameGas: HOWL_WITHDRAW_PROFILE.withdrawFrameGas + 100_000n,
    };
    expect(howlPaymentGasLimit(costlier)).toBe(
      HOWL_PAYMENT_GAS_LIMIT + 110_000n,
    );
    expect(howlWithdrawActionGasLimit(costlier)).toBe(
      HOWL_WITHDRAW_ACTION_GAS_LIMIT + 120_000n,
    );
    expect(() =>
      howlPaymentGasLimit({ ...HOWL_WITHDRAW_PROFILE, payFrameGas: 0n }),
    ).toThrow(/pay frame gas must be positive/);
    expect(() =>
      howlWithdrawActionGasLimit({
        ...HOWL_WITHDRAW_PROFILE,
        withdrawFrameGas: -1n,
      }),
    ).toThrow(/withdraw frame gas must be positive/);
  });

  it("pins the multisig withdraw profile", () => {
    expect(HOWL_WITHDRAW_MULTISIG_PROFILE).toEqual({
      proofBytes: 8_384,
      payFrameGas: 1_010_000n,
      withdrawFrameGas: 827_000n,
    });
  });
});

describe("Howl Nox multisig payment source", () => {
  const multisigArgs: HowlPaymentSourceArgs = {
    adapter: ADAPTER,
    feeAsset: ASSET,
    feeNoteNullifier: PAYMENT_ID,
    feeNoteValue: NOTE_VALUE,
    proveFeeWithdraw: (amount, recipient, intentHash) =>
      Promise.resolve(feeProof(amount, recipient, intentHash)),
  };

  it("declares the multisig profile gas and payment data bound", () => {
    const payment = howlMultisigPaymentSource(multisigArgs);
    expect(payment.adapter).toBe(ADAPTER);
    expect(hexlify(payment.paymentId)).toBe(PAYMENT_ID);
    expect(payment.gasLimit).toBe(
      howlPaymentGasLimit(HOWL_WITHDRAW_MULTISIG_PROFILE),
    );
    expect(payment.paymentDataLength).toBe(
      howlPaymentDataLength(HOWL_WITHDRAW_MULTISIG_PROFILE.proofBytes),
    );
  });

  it("proves the quoted amount to the adapter under the execution intent", async () => {
    const calls: [bigint, string, string][] = [];
    const payment = howlMultisigPaymentSource({
      ...multisigArgs,
      proveFeeWithdraw: (amount, recipient, intentHash) => {
        calls.push([amount, recipient, intentHash.toString()]);
        return Promise.resolve(feeProof(amount, recipient, intentHash));
      },
    });
    const paymentData = await payment.buildPaymentData(paymentRequest);
    expect(calls).toEqual([
      [40n, ADAPTER, howlPaymentIntent(EXECUTION_ID).toString()],
    ]);
    const decoded = AbiCoder.defaultAbiCoder().decode(
      ["bytes", "bytes32[]"],
      paymentData,
    );
    expect(decoded[1][5]).toBe(PAYMENT_ID);
  });

  it("applies the same proof bindings as the standard source", async () => {
    const payment = howlMultisigPaymentSource({
      ...multisigArgs,
      proveFeeWithdraw: (amount, recipient, intentHash) =>
        Promise.resolve(feeProof(amount, EXECUTOR, intentHash)),
    });
    await expect(payment.buildPaymentData(paymentRequest)).rejects.toThrow(
      /recipient is not the payment adapter/,
    );
    await expect(
      howlMultisigPaymentSource(multisigArgs).buildPaymentData({
        ...paymentRequest,
        amount: NOTE_VALUE + 1n,
      }),
    ).rejects.toThrow(/exceeds the fee note value/);
  });

  it("vetoes a multisig withdraw action that spends the fee note", () => {
    const proof = withdrawProof({ 5: PAYMENT_ID });
    const action = getBytes(
      withdrawIface.encodeFunctionData("withdrawMultisig", [
        proof.proof,
        proof.publicInputs,
      ]),
    );
    expect(() =>
      howlMultisigPaymentSource(multisigArgs).checkAction({ data: action }),
    ).toThrow(/spends the fee note/);
    expect(() => source().checkAction({ data: action })).toThrow(
      /spends the fee note/,
    );
    const other = withdrawProof({ 5: OTHER_NOTE });
    howlMultisigPaymentSource(multisigArgs).checkAction({
      data: getBytes(
        withdrawIface.encodeFunctionData("withdrawMultisig", [
          other.proof,
          other.publicInputs,
        ]),
      ),
    });
  });

  it("refuses payment data larger than the declared profile allows", async () => {
    const payment = howlMultisigPaymentSource({
      ...multisigArgs,
      profile: { ...HOWL_WITHDRAW_MULTISIG_PROFILE, proofBytes: 928 },
      proveFeeWithdraw: (amount, recipient, intentHash) =>
        Promise.resolve({
          ...feeProof(amount, recipient, intentHash),
          proof: new Uint8Array(8_384).fill(7),
        }),
    });
    expect(payment.paymentDataLength).toBe(howlPaymentDataLength(928));
    await expect(payment.buildPaymentData(paymentRequest)).rejects.toThrow(
      /above the declared 1600/,
    );
  });

  it("takes an explicit gas limit over the profile", () => {
    expect(
      howlMultisigPaymentSource({ ...multisigArgs, gasLimit: 2_500_000n })
        .gasLimit,
    ).toBe(2_500_000n);
  });
});
