import { describe, expect, it } from "vitest";
import {
  AbiCoder,
  concat,
  type ContractRunner,
  dataSlice,
  getBytes,
  hexlify,
  id,
  Interface,
  keccak256,
  toUtf8Bytes,
} from "ethers";
import { Fr } from "@hisoka/wallets";
import { buildBundle, encodeBundleExecute } from "./bundle.js";
import type { BundleCall } from "./types.js";
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
const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";

function word(value: bigint | string): string {
  return `0x${BigInt(value).toString(16).padStart(64, "0")}`;
}

function flagRunner(
  answer: () => Promise<string>,
  reads: string[] = [],
): ContractRunner {
  return {
    provider: null,
    call: (tx) => {
      reads.push(`${String(tx.to)}:${String(tx.data)}`);
      return answer();
    },
  };
}

const standardAdapter = () => flagRunner(() => Promise.resolve(word(0n)));
const multisigAdapter = () => flagRunner(() => Promise.resolve(word(1n)));

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
    runner: standardAdapter(),
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

function boundCall(data: string): BundleCall {
  return {
    target: DARK_POOL,
    data,
    value: 0n,
    requireSuccess: true,
    approveToken: ZERO_ADDRESS,
    approveAmount: 0n,
    gasLimit: 900_000n,
    returnDataLimit: 0n,
  };
}

function bundleAction(
  nullifier: string,
  calls: readonly string[] = [],
): Uint8Array {
  const bundle = buildBundle(
    { chainId: 31337n, executor: EXECUTOR, darkPool: DARK_POOL },
    calls.map(boundCall),
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
        runner: standardAdapter(),
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
    runner: multisigAdapter(),
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

const spendIface = new Interface([
  "function privateTransfer(bytes proof, bytes32[] publicInputs)",
  "function transferMultisig(bytes proof, bytes32[] publicInputs)",
  "function split(bytes proof, bytes32[] publicInputs)",
  "function splitMultisig(bytes proof, bytes32[] publicInputs)",
  "function join(bytes proof, bytes32[] publicInputs)",
  "function joinMultisig(bytes proof, bytes32[] publicInputs)",
  "function withdraw(bytes proof, bytes32[] publicInputs)",
  "function executeSwap(bytes proof, bytes32[] publicInputs, uint8 swapType, bytes encodedParams, uint256 deadline)",
  "function settleSwap(uint256 solverId, uint256 deadline, bytes solverSignature, bytes proof, bytes32[] publicInputs)",
]);

/** `DarkPool` input counts and nullifier positions (`_transfer`, `_split`, `_join`). */
const SPEND_CASES = [
  { name: "privateTransfer", inputs: 24, nullifiers: [2] },
  { name: "transferMultisig", inputs: 24, nullifiers: [2] },
  { name: "split", inputs: 22, nullifiers: [2] },
  { name: "splitMultisig", inputs: 22, nullifiers: [2] },
  { name: "join", inputs: 14, nullifiers: [2, 3] },
  { name: "joinMultisig", inputs: 14, nullifiers: [2, 3] },
] as const;

function spendAction(
  name: string,
  inputs: number,
  overrides: Record<number, string>,
): string {
  const publicInputs = Array<string>(inputs).fill(word(0n));
  for (const [index, value] of Object.entries(overrides)) {
    publicInputs[Number(index)] = value;
  }
  return spendIface.encodeFunctionData(name, ["0x0102", publicInputs]);
}

function swapAction(nullifier: string): string {
  const proof = withdrawProof({ 5: nullifier });
  return spendIface.encodeFunctionData("executeSwap", [
    proof.proof,
    proof.publicInputs,
    0,
    "0x",
    1893456000n,
  ]);
}

describe("Howl payment source spend veto", () => {
  for (const spend of SPEND_CASES) {
    it(`vetoes ${spend.name} when it spends the fee note`, () => {
      const payment = source();
      for (const position of spend.nullifiers) {
        expect(() =>
          payment.checkAction({
            data: getBytes(
              spendAction(spend.name, spend.inputs, { [position]: PAYMENT_ID }),
            ),
          }),
        ).toThrow(
          new RegExp(
            `spends the fee note through ${spend.name}\\(bytes,bytes32\\[\\]\\) \\(public input ${position}\\)`,
          ),
        );
      }
      const others: Record<number, string> = {};
      for (const position of spend.nullifiers) others[position] = OTHER_NOTE;
      payment.checkAction({
        data: getBytes(spendAction(spend.name, spend.inputs, others)),
      });
      const spare = spend.nullifiers.length === 1 ? 4 : 5;
      payment.checkAction({
        data: getBytes(
          spendAction(spend.name, spend.inputs, { [spare]: PAYMENT_ID }),
        ),
      });
      expect(() =>
        payment.checkAction({
          data: getBytes(spendAction(spend.name, spend.inputs - 1, others)),
        }),
      ).toThrow(new RegExp(`requires ${spend.inputs} public inputs`));
    });
  }

  it("vetoes a Kage settlement that spends the fee note as taker or maker", () => {
    const payment = source();
    const settle = (inputs: number, overrides: Record<number, string>) => {
      const publicInputs = Array<string>(inputs).fill(word(0n));
      for (const [index, value] of Object.entries(overrides)) {
        publicInputs[Number(index)] = value;
      }
      return getBytes(
        spendIface.encodeFunctionData("settleSwap", [
          1n,
          1893456000n,
          "0xabcd",
          "0x0102",
          publicInputs,
        ]),
      );
    };
    for (const position of [3, 4]) {
      expect(() =>
        payment.checkAction({ data: settle(42, { [position]: PAYMENT_ID }) }),
      ).toThrow(
        new RegExp(
          `spends the fee note through settleSwap\\(uint256,uint256,bytes,bytes,bytes32\\[\\]\\) \\(public input ${position}\\)`,
        ),
      );
    }
    payment.checkAction({ data: settle(42, { 3: OTHER_NOTE, 4: OTHER_NOTE }) });
    for (const position of [0, 2, 5, 6, 41]) {
      payment.checkAction({ data: settle(42, { [position]: PAYMENT_ID }) });
    }
    expect(() =>
      payment.checkAction({ data: settle(41, { 3: OTHER_NOTE }) }),
    ).toThrow(/requires 42 public inputs, got 41/);
  });

  it("vetoes a swap whose withdraw spends the fee note", () => {
    const payment = source();
    expect(() =>
      payment.checkAction({ data: getBytes(swapAction(PAYMENT_ID)) }),
    ).toThrow(/spends the fee note through executeSwap/);
    payment.checkAction({ data: getBytes(swapAction(OTHER_NOTE)) });
  });

  it("vetoes a bundle whose bound call spends the fee note", () => {
    const payment = source();
    const nestedWithdraw = hexlify(withdrawAction(PAYMENT_ID));
    expect(() =>
      payment.checkAction({
        data: bundleAction(OTHER_NOTE, [nestedWithdraw]),
      }),
    ).toThrow(/spends the fee note through withdraw\(/);
    expect(() =>
      payment.checkAction({
        data: bundleAction(OTHER_NOTE, [
          "0xdeadbeef",
          spendAction("join", 14, { 3: PAYMENT_ID }),
        ]),
      }),
    ).toThrow(
      /spends the fee note through join\(bytes,bytes32\[\]\) \(public input 3\)/,
    );
    payment.checkAction({
      data: bundleAction(OTHER_NOTE, [
        hexlify(withdrawAction(OTHER_NOTE)),
        "0xdeadbeef",
        "0x",
      ]),
    });
  });

  it("searches nested bundles to a bounded depth and refuses deeper ones", () => {
    const payment = source();
    const nest = (inner: string, levels: number): string => {
      let data = inner;
      for (let level = 0; level < levels; level += 1) {
        data = hexlify(bundleAction(OTHER_NOTE, [data]));
      }
      return data;
    };
    const spendsFee = hexlify(withdrawAction(PAYMENT_ID));
    expect(() =>
      payment.checkAction({ data: getBytes(nest(spendsFee, 4)) }),
    ).toThrow(/spends the fee note through withdraw\(/);
    payment.checkAction({ data: getBytes(nest("0xdeadbeef", 4)) });
    expect(() =>
      payment.checkAction({ data: getBytes(nest("0xdeadbeef", 5)) }),
    ).toThrow(/nests bundles deeper than 4/);
  });

  it("vetoes a bundle whose bound calls do not decode", () => {
    const payment = source();
    const valid = hexlify(bundleAction(OTHER_NOTE, ["0xdeadbeef"]));
    expect(() =>
      payment.checkAction({ data: getBytes(valid.slice(0, -64)) }),
    ).toThrow(/do not decode/);
  });
});

describe("Howl payment adapter kind", () => {
  const MULTISIG_READ = dataSlice(id("MULTISIG()"), 0, 4);

  function sourceAt(
    kind: "standard" | "multisig",
    runner: ContractRunner,
    proved: { count: number },
  ) {
    const args: HowlPaymentSourceArgs = {
      adapter: ADAPTER,
      runner,
      feeAsset: ASSET,
      feeNoteNullifier: PAYMENT_ID,
      feeNoteValue: NOTE_VALUE,
      proveFeeWithdraw: (amount, recipient, intentHash) => {
        proved.count += 1;
        return Promise.resolve(feeProof(amount, recipient, intentHash));
      },
    };
    return kind === "standard"
      ? howlPaymentSource(args)
      : howlMultisigPaymentSource(args);
  }

  it("reads MULTISIG() from the adapter once, before the first proof", async () => {
    for (const [kind, flag] of [
      ["standard", 0n],
      ["multisig", 1n],
    ] as const) {
      const reads: string[] = [];
      const proved = { count: 0 };
      const payment = sourceAt(
        kind,
        flagRunner(() => Promise.resolve(word(flag)), reads),
        proved,
      );
      expect(reads).toEqual([]);
      await payment.buildPaymentData(paymentRequest);
      await payment.buildPaymentData(paymentRequest);
      expect(reads).toEqual([`${ADAPTER}:${MULTISIG_READ}`]);
      expect(proved.count).toBe(2);
    }
  });

  it("refuses the multisig instance for a standard note before proving", async () => {
    const proved = { count: 0 };
    await expect(
      sourceAt("standard", multisigAdapter(), proved).buildPaymentData(
        paymentRequest,
      ),
    ).rejects.toThrow(
      /pulls fees through withdrawMultisig \(MULTISIG\(\) is true\).*use the instance whose MULTISIG\(\) is false/,
    );
    expect(proved.count).toBe(0);
  });

  it("refuses the standard instance for a multisig note before proving", async () => {
    const proved = { count: 0 };
    await expect(
      sourceAt("multisig", standardAdapter(), proved).buildPaymentData(
        paymentRequest,
      ),
    ).rejects.toThrow(
      /pulls fees through withdraw \(MULTISIG\(\) is false\).*use the instance whose MULTISIG\(\) is true/,
    );
    expect(proved.count).toBe(0);
  });

  it("refuses an adapter that does not answer with a boolean word", async () => {
    for (const answer of ["0x", word(2n), `${word(1n)}00`, "nonsense"]) {
      const proved = { count: 0 };
      await expect(
        sourceAt(
          "standard",
          flagRunner(() => Promise.resolve(answer)),
          proved,
        ).buildPaymentData(paymentRequest),
      ).rejects.toThrow(/not a HowlPaymentAdapter/);
      expect(proved.count).toBe(0);
    }
  });

  it("reports a failed read and reads again on the next payment", async () => {
    let attempts = 0;
    const proved = { count: 0 };
    const payment = sourceAt(
      "standard",
      flagRunner(() => {
        attempts += 1;
        return attempts === 1
          ? Promise.reject(new Error("connection reset"))
          : Promise.resolve(word(0n));
      }),
      proved,
    );
    await expect(payment.buildPaymentData(paymentRequest)).rejects.toThrow(
      `Reading MULTISIG() from payment adapter ${ADAPTER} failed: connection reset`,
    );
    expect(proved.count).toBe(0);
    await payment.buildPaymentData(paymentRequest);
    expect(attempts).toBe(2);
    expect(proved.count).toBe(1);
  });

  it("requires a runner that can eth_call", () => {
    expect(() =>
      sourceAt("standard", { provider: null }, { count: 0 }),
    ).toThrow(/runner that can eth_call/);
  });
});
