import { describe, it, expect } from "vitest";
import { AbiCoder, Interface, keccak256 } from "ethers";
import { Fr } from "@hisoka/wallets";
import {
  buildBundle,
  buildGasPaymentBundle,
  buildSwapFeeBundle,
  treasuryDepositCall,
} from "./bundle.js";
import { BundleCall } from "./types.js";

const TREASURY = "0x1111111111111111111111111111111111111111";
const FEE_ASSET = "0x2222222222222222222222222222222222222222";
const ROUTER = "0x3333333333333333333333333333333333333333";
const TOKEN_OUT = "0x4444444444444444444444444444444444444444";
const USER = "0x5555555555555555555555555555555555555555";

const depositRewardsIface = new Interface([
  "function depositRewards(address asset, uint256 amount)",
]);

const BUNDLE_CALL_TUPLE =
  "tuple(address target, bytes data, uint256 value, bool requireSuccess, address approveToken, uint256 approveAmount)[]";

function reEncodeIntentHash(
  boundCalls: BundleCall[],
  deadline: bigint,
  assetsToClear: string[],
): bigint {
  const encoded = AbiCoder.defaultAbiCoder().encode(
    [BUNDLE_CALL_TUPLE, "uint256", "address[]"],
    [
      boundCalls.map((c) => [
        c.target,
        c.data,
        c.value,
        c.requireSuccess,
        c.approveToken,
        c.approveAmount,
      ]),
      deadline,
      assetsToClear,
    ],
  );
  return BigInt(keccak256(encoded)) % Fr.MODULUS;
}

describe("Executor bundle builder", () => {
  const deadline = 1893456000n;

  it("intent hash equals keccak(abi.encode) reduced into the field, deterministically", () => {
    const call = treasuryDepositCall(TREASURY, FEE_ASSET, 40n);
    const a = buildBundle([call], deadline, []);
    const b = buildBundle([call], deadline, []);

    expect(a.intentHash.toString()).toBe(b.intentHash.toString());
    expect(a.intentHash.toBigInt()).toBe(
      reEncodeIntentHash([call], deadline, []),
    );
    expect(a.intentHash.toBigInt() < Fr.MODULUS).toBe(true);
  });

  it("binds every call field: mutating any part changes the hash", () => {
    const base = treasuryDepositCall(TREASURY, FEE_ASSET, 40n);
    const h0 = buildBundle([base], deadline, []).intentHash.toBigInt();

    const mutated: BundleCall = { ...base, approveAmount: 41n };
    expect(buildBundle([mutated], deadline, []).intentHash.toBigInt()).not.toBe(
      h0,
    );
    expect(
      buildBundle([base], deadline + 1n, []).intentHash.toBigInt(),
    ).not.toBe(h0);
    expect(
      buildBundle([base], deadline, [FEE_ASSET]).intentHash.toBigInt(),
    ).not.toBe(h0);
  });

  it("buildGasPaymentBundle (Mode 1): single exact-approve treasury deposit, requireSuccess", () => {
    const bundle = buildGasPaymentBundle(FEE_ASSET, 40n, TREASURY, deadline);

    expect(bundle.boundCalls).toHaveLength(1);
    expect(bundle.assetsToClear).toEqual([]);

    const call = bundle.boundCalls[0]!;
    expect(call.target).toBe(TREASURY);
    expect(call.requireSuccess).toBe(true);
    expect(call.value).toBe(0n);
    expect(call.approveToken).toBe(FEE_ASSET);
    expect(call.approveAmount).toBe(40n);

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
    };
    const bundle = buildSwapFeeBundle({
      router: ROUTER,
      swapCalldata,
      tokenIn: FEE_ASSET,
      amountIn: 1000n,
      tokenOut: TOKEN_OUT,
      treasury: TREASURY,
      feeAmount: 25n,
      distributionCalls: [returnCall],
      deadline,
    });

    expect(bundle.boundCalls).toHaveLength(3);
    expect(bundle.assetsToClear).toEqual([FEE_ASSET, TOKEN_OUT]);

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
      reEncodeIntentHash(bundle.boundCalls, deadline, [FEE_ASSET, TOKEN_OUT]),
    );
  });
});
