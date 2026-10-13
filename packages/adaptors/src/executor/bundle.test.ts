import { describe, it, expect } from "vitest";
import { AbiCoder, Interface, keccak256 } from "ethers";
import { Fr } from "@hisoka/wallets";
import {
  buildBundle,
  buildFeePaymentBundle,
  buildSwapFeeBundle,
  bundleActionGasLimit,
  encodeBundleExecute,
  treasuryDepositCall,
} from "./bundle.js";
import { HOWL_WITHDRAW_ACTION_GAS_LIMIT } from "./howl-payment.js";
import { BundleCall, BundleDomain } from "./types.js";

const TREASURY = "0x1111111111111111111111111111111111111111";
const FEE_ASSET = "0x2222222222222222222222222222222222222222";
const ROUTER = "0x3333333333333333333333333333333333333333";
const TOKEN_OUT = "0x4444444444444444444444444444444444444444";
const USER = "0x5555555555555555555555555555555555555555";
const EXECUTOR = "0x6666666666666666666666666666666666666666";
const DARK_POOL = "0x7777777777777777777777777777777777777777";
const DOMAIN: BundleDomain = {
  chainId: 43113n,
  executor: EXECUTOR,
  darkPool: DARK_POOL,
};

const depositRewardsIface = new Interface([
  "function depositRewards(address asset, uint256 amount)",
]);

const BUNDLE_CALL_TUPLE =
  "tuple(address target, bytes data, uint256 value, bool requireSuccess, address approveToken, uint256 approveAmount, uint256 gasLimit, uint256 returnDataLimit)[]";

function reEncodeIntentHash(
  domain: BundleDomain,
  boundCalls: BundleCall[],
  deadline: bigint,
  trackedAssets: string[],
  recipients: string[],
): bigint {
  const encoded = AbiCoder.defaultAbiCoder().encode(
    [
      "uint256",
      "uint256",
      "address",
      "address",
      BUNDLE_CALL_TUPLE,
      "uint256",
      "address[]",
      "address[]",
    ],
    [
      2n,
      domain.chainId,
      domain.executor,
      domain.darkPool,
      boundCalls.map((c) => [
        c.target,
        c.data,
        c.value,
        c.requireSuccess,
        c.approveToken,
        c.approveAmount,
        c.gasLimit,
        c.returnDataLimit,
      ]),
      deadline,
      trackedAssets,
      recipients,
    ],
  );
  return BigInt(keccak256(encoded)) % Fr.MODULUS;
}

describe("Executor bundle builder", () => {
  const deadline = 1893456000n;

  it("intent hash equals keccak(abi.encode) reduced into the field, deterministically", () => {
    const call = treasuryDepositCall(TREASURY, FEE_ASSET, 40n, 200_000n);
    const a = buildBundle(DOMAIN, [call], deadline, [FEE_ASSET], [USER]);
    const b = buildBundle(DOMAIN, [call], deadline, [FEE_ASSET], [USER]);

    expect(a.intentHash.toString()).toBe(b.intentHash.toString());
    expect(a.intentHash.toBigInt()).toBe(
      reEncodeIntentHash(DOMAIN, [call], deadline, [FEE_ASSET], [USER]),
    );
    expect(a.intentHash.toBigInt() < Fr.MODULUS).toBe(true);
  });

  it("binds every call field: mutating any part changes the hash", () => {
    const base = treasuryDepositCall(TREASURY, FEE_ASSET, 40n, 200_000n);
    const h0 = buildBundle(
      DOMAIN,
      [base],
      deadline,
      [FEE_ASSET],
      [USER],
    ).intentHash.toBigInt();

    const mutated: BundleCall = { ...base, approveAmount: 41n };
    expect(
      buildBundle(
        DOMAIN,
        [mutated],
        deadline,
        [FEE_ASSET],
        [USER],
      ).intentHash.toBigInt(),
    ).not.toBe(h0);
    expect(
      buildBundle(
        DOMAIN,
        [base],
        deadline + 1n,
        [FEE_ASSET],
        [USER],
      ).intentHash.toBigInt(),
    ).not.toBe(h0);
    expect(
      buildBundle(
        DOMAIN,
        [base],
        deadline,
        [TOKEN_OUT],
        [USER],
      ).intentHash.toBigInt(),
    ).not.toBe(h0);
    expect(
      buildBundle(
        DOMAIN,
        [base],
        deadline,
        [FEE_ASSET],
        [TREASURY],
      ).intentHash.toBigInt(),
    ).not.toBe(h0);
    expect(
      buildBundle(
        { ...DOMAIN, chainId: DOMAIN.chainId + 1n },
        [base],
        deadline,
        [FEE_ASSET],
        [USER],
      ).intentHash.toBigInt(),
    ).not.toBe(h0);
  });

  it("buildFeePaymentBundle: single exact-approve treasury deposit, requireSuccess", () => {
    const bundle = buildFeePaymentBundle(
      DOMAIN,
      FEE_ASSET,
      40n,
      TREASURY,
      deadline,
      200_000n,
    );

    expect(bundle.boundCalls).toHaveLength(1);
    expect(bundle.trackedAssets).toEqual([FEE_ASSET]);
    expect(bundle.recipients).toEqual([]);

    const call = bundle.boundCalls[0]!;
    expect(call.target).toBe(TREASURY);
    expect(call.requireSuccess).toBe(true);
    expect(call.value).toBe(0n);
    expect(call.approveToken).toBe(FEE_ASSET);
    expect(call.approveAmount).toBe(40n);
    expect(call.gasLimit).toBe(200_000n);
    expect(call.returnDataLimit).toBe(0n);

    const decoded = depositRewardsIface.decodeFunctionData(
      "depositRewards",
      call.data,
    );
    expect(decoded[0]).toBe(FEE_ASSET);
    expect(decoded[1]).toBe(40n);
  });

  it("buildSwapFeeBundle (Mode 2): swap + fee + distribution, clears both assets", () => {
    const swapCalldata = "0xdeadbeef";
    const returnCall: BundleCall = {
      target: USER,
      data: "0x",
      value: 0n,
      requireSuccess: false,
      approveToken: "0x0000000000000000000000000000000000000000",
      approveAmount: 0n,
      gasLimit: 100_000n,
      returnDataLimit: 32n,
    };
    const bundle = buildSwapFeeBundle({
      domain: DOMAIN,
      router: ROUTER,
      swapCalldata,
      tokenIn: FEE_ASSET,
      amountIn: 1000n,
      tokenOut: TOKEN_OUT,
      treasury: TREASURY,
      feeAmount: 25n,
      swapGasLimit: 500_000n,
      feeCallGasLimit: 200_000n,
      distributionCalls: [returnCall],
      recipients: [USER],
      deadline,
    });

    expect(bundle.boundCalls).toHaveLength(3);
    expect(bundle.trackedAssets).toEqual([FEE_ASSET, TOKEN_OUT]);
    expect(bundle.recipients).toEqual([USER]);

    const [swap, fee, dist] = bundle.boundCalls;
    expect(swap!.target).toBe(ROUTER);
    expect(swap!.data).toBe(swapCalldata);
    expect(swap!.requireSuccess).toBe(true);
    expect(swap!.approveToken).toBe(FEE_ASSET);
    expect(swap!.approveAmount).toBe(1000n);

    expect(fee!.target).toBe(TREASURY);
    expect(fee!.requireSuccess).toBe(true);
    expect(fee!.approveToken).toBe(TOKEN_OUT);
    expect(fee!.approveAmount).toBe(25n);

    expect(dist).toBe(returnCall);
    expect(bundle.intentHash.toBigInt()).toBe(
      reEncodeIntentHash(
        DOMAIN,
        bundle.boundCalls,
        deadline,
        [FEE_ASSET, TOKEN_OUT],
        [USER],
      ),
    );
  });

  describe("encodeBundleExecute", () => {
    const executeIface = new Interface([
      `function execute(bytes proof, bytes32[] publicInputs, ${BUNDLE_CALL_TUPLE} boundCalls, uint256 deadline, address[] trackedAssets, address[] recipients)`,
    ]);
    const call = treasuryDepositCall(TREASURY, FEE_ASSET, 40n, 200_000n);
    const bundle = buildBundle(DOMAIN, [call], deadline, [FEE_ASSET], [USER]);
    const word = (value: bigint | string) =>
      `0x${BigInt(value).toString(16).padStart(64, "0")}`;
    const publicInputs = (recipient: string, intent: string) => {
      const inputs = Array<string>(17).fill(word(0n));
      inputs[1] = word(recipient);
      inputs[2] = intent;
      return inputs;
    };

    it("encodes the executor call with the proof and the exact bundle", () => {
      const inputs = publicInputs(EXECUTOR, bundle.intentHash.toString());
      const calldata = encodeBundleExecute(bundle, {
        proof: "0x010203",
        publicInputs: inputs,
      });
      expect(calldata.slice(0, 10)).toBe("0xc1ab9754");
      const decoded = executeIface.decodeFunctionData("execute", calldata);
      expect(decoded[0]).toBe("0x010203");
      expect([...decoded[1]]).toEqual(inputs);
      expect(decoded[2]).toHaveLength(1);
      expect([...decoded[2][0]]).toEqual([
        call.target,
        call.data,
        call.value,
        call.requireSuccess,
        call.approveToken,
        call.approveAmount,
        call.gasLimit,
        call.returnDataLimit,
      ]);
      expect(decoded[3]).toBe(deadline);
      expect([...decoded[4]]).toEqual([FEE_ASSET]);
      expect([...decoded[5]]).toEqual([USER]);
    });

    it("rejects a proof that is not the bundle's withdraw to the executor", () => {
      const intent = bundle.intentHash.toString();
      expect(() =>
        encodeBundleExecute(bundle, {
          proof: "0x01",
          publicInputs: publicInputs(USER, intent),
        }),
      ).toThrow(/recipient/);
      expect(() =>
        encodeBundleExecute(bundle, {
          proof: "0x01",
          publicInputs: publicInputs(EXECUTOR, word(1n)),
        }),
      ).toThrow(/intent/);
      expect(() =>
        encodeBundleExecute(bundle, {
          proof: "0x01",
          publicInputs: publicInputs(EXECUTOR, intent).slice(1),
        }),
      ).toThrow(/17 public inputs/);
    });
  });

  describe("bundleActionGasLimit", () => {
    const plainCall = (gasLimit: bigint, data = "0x"): BundleCall => ({
      target: USER,
      data,
      value: 0n,
      requireSuccess: true,
      approveToken: "0x0000000000000000000000000000000000000000",
      approveAmount: 0n,
      gasLimit,
      returnDataLimit: 0n,
    });
    const limit = (
      calls: BundleCall[],
      trackedAssets: string[] = [FEE_ASSET],
    ) =>
      bundleActionGasLimit(
        buildBundle(DOMAIN, calls, deadline, trackedAssets, [USER]),
      );
    const base = HOWL_WITHDRAW_ACTION_GAS_LIMIT + 100_000n + 24_000n;

    it("reserves the withdraw, the executor overhead and one tracked asset", () => {
      expect(limit([])).toBe(base);
    });

    it("reserves what the executor demands before forwarding each call", () => {
      expect(limit([plainCall(100_000n)])).toBe(base + 162_540n + 12_000n);
      expect(limit([plainCall(100_000n), plainCall(3n)])).toBe(
        base + 162_540n + 60_956n + 2n * 12_000n,
      );
    });

    it("adds approvals, tracked assets and bound calldata", () => {
      const approving = treasuryDepositCall(TREASURY, FEE_ASSET, 40n, 3n);
      expect(limit([approving], [FEE_ASSET, TOKEN_OUT])).toBe(
        base + 24_000n + 60_956n + 12_000n + 60_000n + 68n * 3n,
      );
      expect(limit([plainCall(3n, `0x${"11".repeat(1000)}`)])).toBe(
        base + 60_956n + 12_000n + 3_000n,
      );
    });

    it("refuses calldata beyond the size the bound covers", () => {
      expect(() => limit([plainCall(3n, `0x${"11".repeat(32_001)}`)])).toThrow(
        /exceeds the 32000 bytes/,
      );
    });
  });
});
