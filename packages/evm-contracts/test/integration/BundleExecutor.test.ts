import { expect } from "chai";
import { ethers } from "hardhat";
import { loadFixture, time } from "@nomicfoundation/hardhat-network-helpers";
import {
  deployDarkPoolFixture,
  makeDeposit,
  mintSelfNote,
  evenYEphemeral,
  COMPLIANCE_PK,
} from "../helpers/fixtures";
import { toFr, addressToFr, Fr } from "@hisoka/wallets";
import { proveWithdraw, WithdrawInputs } from "@hisoka/prover";
import {
  buildBundle,
  buildGasPaymentBundle,
  buildSwapFeeBundle,
  treasuryDepositCall,
  BundleCall,
} from "@hisoka/adaptors";
import {
  BundleExecutor__factory,
  MockTarget,
} from "../../typechain-types";

const ZERO = "0x0000000000000000000000000000000000000000";

async function deployExecutorFixture() {
  const base = await deployDarkPoolFixture();
  const executor = await (
    (await ethers.getContractFactory(
      "BundleExecutor",
    )) as unknown as BundleExecutor__factory
  ).deploy(await base.darkPool.getAddress());
  const mockTarget = (await (
    await ethers.getContractFactory("MockTarget")
  ).deploy()) as unknown as MockTarget;
  return { ...base, executor, mockTarget };
}

/** Deposit `depositAmount` for alice (single-leaf tree at index 0) and prove a withdraw of `withdrawAmount`
 * to the executor, bound to `intentHash`. The change (`depositAmount - withdrawAmount`) re-shields to alice. */
async function proveWithdrawToExecutor(
  ctx: Awaited<ReturnType<typeof deployExecutorFixture>>,
  depositAmount: bigint,
  withdrawAmount: bigint,
  intentHash: Fr,
) {
  const { darkPool, alice, token, executor } = ctx;
  const dep = await makeDeposit(darkPool, token, alice, depositAmount);
  const assetFr = addressToFr(await token.getAddress());
  const changeEph = evenYEphemeral(4242n);
  const change = await mintSelfNote(
    changeEph,
    depositAmount - withdrawAmount,
    dep.spendScalar,
    assetFr,
  );
  const inputs: WithdrawInputs = {
    withdrawValue: toFr(withdrawAmount),
    recipient: addressToFr(await executor.getAddress()),
    currentTimestamp: await time.latest(),
    intentHash,
    compliancePk: COMPLIANCE_PK,
    oldNote: dep.built.note,
    spendScalar: dep.spendScalar,
    oldNoteIndex: 0,
    oldNotePath: Array(32).fill(toFr(0n)),
    changeNote: change.note,
    changeEph,
  };
  const proof = await proveWithdraw(inputs);
  return { proof, nullifier: proof.publicInputs[6] };
}

describe("Integration: BundleExecutor", function () {
  it("intentHash KAT: SDK bundle == on-chain intentHashOf (Mode 1 + Mode 2)", async function () {
    const { executor } = await loadFixture(deployExecutorFixture);
    const deadline = 1893456000n;

    const mode1 = buildGasPaymentBundle(
      "0x2222222222222222222222222222222222222222",
      40n,
      "0x1111111111111111111111111111111111111111",
      deadline,
    );
    const onchain1 = await executor.intentHashOf(
      mode1.boundCalls,
      mode1.deadline,
      mode1.assetsToClear,
    );
    expect(onchain1).to.equal(mode1.intentHash.toBigInt());
    expect(ethers.toBeHex(onchain1, 32)).to.equal(mode1.intentHash.toString());

    const mode2 = buildSwapFeeBundle({
      router: "0x3333333333333333333333333333333333333333",
      swapCalldata: "0xdeadbeef",
      tokenIn: "0x2222222222222222222222222222222222222222",
      amountIn: 1000n,
      tokenOut: "0x4444444444444444444444444444444444444444",
      treasury: "0x1111111111111111111111111111111111111111",
      feeAmount: 25n,
      distributionCalls: [
        {
          target: "0x5555555555555555555555555555555555555555",
          data: "0x",
          value: 0n,
          requireSuccess: false,
          approveToken: ZERO,
          approveAmount: 0n,
        },
      ],
      deadline,
    });
    const onchain2 = await executor.intentHashOf(
      mode2.boundCalls,
      mode2.deadline,
      mode2.assetsToClear,
    );
    expect(onchain2).to.equal(mode2.intentHash.toBigInt());

    console.log(`   [KAT] Mode-1 intentHash = ${mode1.intentHash.toString()}`);
    console.log(`   [KAT] Mode-2 intentHash = ${mode2.intentHash.toString()}`);
  });

  it("Mode 1: atomic withdraw -> treasury deposit -> zero residual", async function () {
    const ctx = await loadFixture(deployExecutorFixture);
    const { darkPool, token, executor, rewardPool } = ctx;
    const tokenAddr = await token.getAddress();
    const executorAddr = await executor.getAddress();

    const feeAmount = 40n;
    const deadline = BigInt((await time.latest()) + 3600);
    const bundle = buildGasPaymentBundle(
      tokenAddr,
      feeAmount,
      await rewardPool.getAddress(),
      deadline,
    );

    const { proof, nullifier } = await proveWithdrawToExecutor(
      ctx,
      100n,
      feeAmount,
      bundle.intentHash,
    );

    const tx = await executor.execute(
      proof.proof,
      proof.publicInputs,
      bundle.boundCalls,
      bundle.deadline,
      bundle.assetsToClear,
    );
    const receipt = await tx.wait();

    await expect(tx)
      .to.emit(rewardPool, "RewardsDeposited")
      .withArgs(tokenAddr, executorAddr, feeAmount);
    await expect(tx).to.emit(executor, "BundleExecuted");

    expect(await darkPool.isNullifierSpent(nullifier)).to.equal(true);
    expect(await rewardPool.totalCollected(tokenAddr)).to.equal(feeAmount);
    expect(await token.balanceOf(await rewardPool.getAddress())).to.equal(
      feeAmount,
    );
    expect(await token.balanceOf(executorAddr)).to.equal(0n);
    expect(
      await token.allowance(executorAddr, await rewardPool.getAddress()),
    ).to.equal(0n);

    console.log(`   [gas] Mode-1 execute = ${receipt?.gasUsed?.toString()}`);
  });

  it("requireSuccess=false: failing call continues, bundle still settles", async function () {
    const ctx = await loadFixture(deployExecutorFixture);
    const { token, executor, rewardPool, mockTarget } = ctx;
    const tokenAddr = await token.getAddress();
    const executorAddr = await executor.getAddress();
    const feeAmount = 40n;
    const deadline = BigInt((await time.latest()) + 3600);

    const failCall: BundleCall = {
      target: await mockTarget.getAddress(),
      data: mockTarget.interface.encodeFunctionData("failFn", ["skip"]),
      value: 0n,
      requireSuccess: false,
      approveToken: ZERO,
      approveAmount: 0n,
    };
    const bundle = buildBundle(
      [
        failCall,
        treasuryDepositCall(
          await rewardPool.getAddress(),
          tokenAddr,
          feeAmount,
        ),
      ],
      deadline,
      [],
    );

    const { proof } = await proveWithdrawToExecutor(
      ctx,
      100n,
      feeAmount,
      bundle.intentHash,
    );

    const tx = await executor.execute(
      proof.proof,
      proof.publicInputs,
      bundle.boundCalls,
      bundle.deadline,
      bundle.assetsToClear,
    );

    await expect(tx).to.emit(executor, "CallFailed");
    await expect(tx)
      .to.emit(rewardPool, "RewardsDeposited")
      .withArgs(tokenAddr, executorAddr, feeAmount);
    expect(await token.balanceOf(executorAddr)).to.equal(0n);
  });

  it("requireSuccess=true: failing call reverts the whole bundle (atomic)", async function () {
    const ctx = await loadFixture(deployExecutorFixture);
    const { darkPool, executor, mockTarget } = ctx;
    const feeAmount = 40n;
    const deadline = BigInt((await time.latest()) + 3600);

    const failCall: BundleCall = {
      target: await mockTarget.getAddress(),
      data: mockTarget.interface.encodeFunctionData("failFn", ["boom"]),
      value: 0n,
      requireSuccess: true,
      approveToken: ZERO,
      approveAmount: 0n,
    };
    const bundle = buildBundle([failCall], deadline, []);

    const { proof, nullifier } = await proveWithdrawToExecutor(
      ctx,
      100n,
      feeAmount,
      bundle.intentHash,
    );

    await expect(
      executor.execute(
        proof.proof,
        proof.publicInputs,
        bundle.boundCalls,
        bundle.deadline,
        bundle.assetsToClear,
      ),
    ).to.be.revertedWith("boom");

    expect(await darkPool.isNullifierSpent(nullifier)).to.equal(false);
  });

  it("expired deadline reverts before any withdraw", async function () {
    const { executor } = await loadFixture(deployExecutorFixture);
    const deadline = BigInt((await time.latest()) - 3600);
    const dummyInputs = Array(19).fill(ethers.ZeroHash);

    await expect(
      executor.execute("0x", dummyInputs, [], deadline, []),
    ).to.be.revertedWithCustomError(executor, "ExpiredDeadline");
  });

  it("raw DarkPool.withdraw to the executor from an EOA reverts OnlyRecipientMayPull", async function () {
    const ctx = await loadFixture(deployExecutorFixture);
    const { darkPool, alice } = ctx;

    const { proof } = await proveWithdrawToExecutor(ctx, 100n, 40n, toFr(0n));

    await expect(
      darkPool.connect(alice).withdraw(proof.proof, proof.publicInputs),
    ).to.be.revertedWithCustomError(darkPool, "OnlyRecipientMayPull");
  });
});
