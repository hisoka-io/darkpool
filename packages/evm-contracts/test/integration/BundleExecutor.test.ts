import { expect } from "chai";
import { ethers } from "hardhat";
import { loadFixture, time } from "@nomicfoundation/hardhat-network-helpers";
import {
  deployDarkPoolFixture,
  makeDeposit,
  mintSelfNote,
  evenYEphemeral,
  newSeededTree,
  COMPLIANCE_PK,
} from "../helpers/fixtures";
import { toFr, addressToFr, packParents, Fr } from "@hisoka/wallets";
import { proveWithdraw, WithdrawInputs } from "@hisoka/prover";
import {
  buildBundle,
  buildFeePaymentBundle,
  buildSwapFeeBundle,
  treasuryDepositCall,
  BundleCall,
} from "@hisoka/adaptors";
import {
  BundleExecutor__factory,
  MockERC20,
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

async function domainFor(
  executor: { getAddress(): Promise<string> },
  darkPool: { getAddress(): Promise<string> },
) {
  return {
    chainId: (await ethers.provider.getNetwork()).chainId,
    executor: await executor.getAddress(),
    darkPool: await darkPool.getAddress(),
  };
}

async function proveWithdrawToExecutor(
  ctx: Awaited<ReturnType<typeof deployExecutorFixture>>,
  depositAmount: bigint,
  withdrawAmount: bigint,
  intentHash: Fr,
) {
  const { darkPool, alice, token, executor } = ctx;
  const dep = await makeDeposit(darkPool, token, alice, depositAmount);
  const tree = await newSeededTree();
  await tree.insert(dep.commitment);
  const assetFr = addressToFr(await token.getAddress());
  const changeEph = evenYEphemeral(4242n);
  const change = await mintSelfNote(
    changeEph,
    depositAmount - withdrawAmount,
    dep.spendScalar,
    assetFr,
    packParents([{ leafIndex: 1 }, { leafIndex: 0 }]),
  );
  const inputs: WithdrawInputs = {
    withdrawValue: toFr(withdrawAmount),
    recipient: addressToFr(await executor.getAddress()),
    intentHash,
    compliancePk: COMPLIANCE_PK,
    oldNote: dep.built.note,
    spendScalar: dep.spendScalar,
    oldNoteIndex: 1,
    oldNotePath: tree.getMerklePath(1),
    changeNote: change.note,
    changeEph,
  };
  const proof = await proveWithdraw(inputs);
  return { proof, nullifier: proof.publicInputs[5] };
}

describe("Integration: BundleExecutor", function () {
  it("intentHash KAT: SDK bundle == on-chain intentHashOf (Mode 1 + Mode 2)", async function () {
    const { executor, darkPool } = await loadFixture(deployExecutorFixture);
    const domain = await domainFor(executor, darkPool);
    const deadline = 1893456000n;

    const mode1 = buildFeePaymentBundle(
      domain,
      "0x2222222222222222222222222222222222222222",
      40n,
      "0x1111111111111111111111111111111111111111",
      deadline,
      200_000n,
    );
    const onchain1 = await executor.intentHashOf(
      mode1.boundCalls,
      mode1.deadline,
      mode1.trackedAssets,
      mode1.recipients,
    );
    expect(onchain1).to.equal(mode1.intentHash.toBigInt());
    expect(ethers.toBeHex(onchain1, 32)).to.equal(mode1.intentHash.toString());

    const mode2 = buildSwapFeeBundle({
      domain,
      router: "0x3333333333333333333333333333333333333333",
      swapCalldata: "0xdeadbeef",
      tokenIn: "0x2222222222222222222222222222222222222222",
      amountIn: 1000n,
      tokenOut: "0x4444444444444444444444444444444444444444",
      treasury: "0x1111111111111111111111111111111111111111",
      feeAmount: 25n,
      swapGasLimit: 500_000n,
      feeCallGasLimit: 200_000n,
      distributionCalls: [
        {
          target: "0x5555555555555555555555555555555555555555",
          data: "0x",
          value: 0n,
          requireSuccess: false,
          approveToken: ZERO,
          approveAmount: 0n,
          gasLimit: 200_000n,
          returnDataLimit: 32n,
        },
      ],
      recipients: ["0x5555555555555555555555555555555555555555"],
      deadline,
    });
    const onchain2 = await executor.intentHashOf(
      mode2.boundCalls,
      mode2.deadline,
      mode2.trackedAssets,
      mode2.recipients,
    );
    expect(onchain2).to.equal(mode2.intentHash.toBigInt());

    console.log(`   [KAT] Mode-1 intentHash = ${mode1.intentHash.toString()}`);
    console.log(`   [KAT] Mode-2 intentHash = ${mode2.intentHash.toString()}`);
  });

  it("Mode 1: atomic withdraw -> treasury deposit -> starting balance restored", async function () {
    const ctx = await loadFixture(deployExecutorFixture);
    const { darkPool, token, executor, rewardPool } = ctx;
    const tokenAddr = await token.getAddress();
    const executorAddr = await executor.getAddress();

    const feeAmount = 40n;
    const deadline = BigInt((await time.latest()) + 3600);
    const bundle = buildFeePaymentBundle(
      await domainFor(executor, darkPool),
      tokenAddr,
      feeAmount,
      await rewardPool.getAddress(),
      deadline,
      200_000n,
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
      bundle.trackedAssets,
      bundle.recipients,
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
    const { darkPool, token, executor, rewardPool, mockTarget } = ctx;
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
      gasLimit: 200_000n,
      returnDataLimit: 256n,
    };
    const bundle = buildBundle(
      await domainFor(executor, darkPool),
      [
        failCall,
        treasuryDepositCall(
          await rewardPool.getAddress(),
          tokenAddr,
          feeAmount,
          200_000n,
        ),
      ],
      deadline,
      [tokenAddr],
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
      bundle.trackedAssets,
      bundle.recipients,
    );

    await expect(tx).to.emit(executor, "CallFailed");
    await expect(tx)
      .to.emit(rewardPool, "RewardsDeposited")
      .withArgs(tokenAddr, executorAddr, feeAmount);
    expect(await token.balanceOf(executorAddr)).to.equal(0n);
  });

  it("requireSuccess=true: failing call reverts the whole bundle (atomic)", async function () {
    const ctx = await loadFixture(deployExecutorFixture);
    const { darkPool, token, executor, mockTarget } = ctx;
    const feeAmount = 40n;
    const deadline = BigInt((await time.latest()) + 3600);

    const failCall: BundleCall = {
      target: await mockTarget.getAddress(),
      data: mockTarget.interface.encodeFunctionData("failFn", ["boom"]),
      value: 0n,
      requireSuccess: true,
      approveToken: ZERO,
      approveAmount: 0n,
      gasLimit: 200_000n,
      returnDataLimit: 256n,
    };
    const bundle = buildBundle(
      await domainFor(executor, darkPool),
      [failCall],
      deadline,
      [await token.getAddress()],
      [],
    );

    const { proof, nullifier } = await proveWithdrawToExecutor(
      ctx,
      100n,
      feeAmount,
      bundle.intentHash,
    );

    const encodedError = ethers.concat([
      "0x08c379a0",
      ethers.AbiCoder.defaultAbiCoder().encode(["string"], ["boom"]),
    ]);
    await expect(
      executor.execute(
        proof.proof,
        proof.publicInputs,
        bundle.boundCalls,
        bundle.deadline,
        bundle.trackedAssets,
        bundle.recipients,
      ),
    )
      .to.be.revertedWithCustomError(executor, "RequiredCallFailed")
      .withArgs(
        0,
        ethers.getBytes(encodedError).length,
        ethers.keccak256(encodedError),
      );

    expect(await darkPool.isNullifierSpent(nullifier)).to.equal(false);
  });

  it("rejects an approval asset omitted from the tracked balance set", async function () {
    const ctx = await loadFixture(deployExecutorFixture);
    const { darkPool, token, executor, rewardPool, mockTarget } = ctx;
    const tokenAddr = await token.getAddress();
    const executorAddr = await executor.getAddress();

    const tokenB = (await (
      await ethers.getContractFactory("MockERC20")
    ).deploy("Strand", "STR", 18)) as unknown as MockERC20;
    const tokenBAddr = await tokenB.getAddress();

    const feeAmount = 40n;
    const strandAmount = 1000n;
    const deadline = BigInt((await time.latest()) + 3600);

    // A pre-existing balance does not excuse omitting an approval asset from the signed tracked set.
    await tokenB.mint(executorAddr, strandAmount);

    const strandCall: BundleCall = {
      target: await mockTarget.getAddress(),
      data: mockTarget.interface.encodeFunctionData("successFn", ["noop"]),
      value: 0n,
      requireSuccess: false,
      approveToken: tokenBAddr,
      approveAmount: strandAmount,
      gasLimit: 200_000n,
      returnDataLimit: 32n,
    };
    const bundle = buildBundle(
      await domainFor(executor, darkPool),
      [
        treasuryDepositCall(
          await rewardPool.getAddress(),
          tokenAddr,
          feeAmount,
          200_000n,
        ),
        strandCall,
      ],
      deadline,
      [tokenAddr],
      [],
    );

    const { proof } = await proveWithdrawToExecutor(
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
        bundle.trackedAssets,
        bundle.recipients,
      ),
    )
      .to.be.revertedWithCustomError(executor, "UntrackedApprovalAsset")
      .withArgs(tokenBAddr);
  });

  it("expired deadline reverts before any withdraw", async function () {
    const { executor } = await loadFixture(deployExecutorFixture);
    const deadline = BigInt((await time.latest()) - 3600);
    const dummyInputs = Array(17).fill(ethers.ZeroHash);

    await expect(
      executor.execute("0x", dummyInputs, [], deadline, [], []),
    ).to.be.revertedWithCustomError(executor, "ExpiredDeadline");
  });

  it("raw DarkPool.withdraw to the executor from an EOA is refused: no pull is open", async function () {
    const ctx = await loadFixture(deployExecutorFixture);
    const { darkPool, alice, executor } = ctx;
    const executorAddr = await executor.getAddress();

    const { proof, nullifier } = await proveWithdrawToExecutor(
      ctx,
      100n,
      40n,
      toFr(0n),
    );

    await expect(
      darkPool.connect(alice).withdraw(proof.proof, proof.publicInputs),
    )
      .to.be.revertedWithCustomError(darkPool, "RecipientCannotAcceptWithdraw")
      .withArgs(executorAddr);

    expect(await darkPool.isNullifierSpent(nullifier)).to.equal(false);
    expect(await ctx.token.balanceOf(executorAddr)).to.equal(0n);
  });

  it("reentrancy: a bound call that re-enters execute is blocked by nonReentrant", async function () {
    const ctx = await loadFixture(deployExecutorFixture);
    const { token, executor } = ctx;
    const attacker = await (
      await ethers.getContractFactory("ReentrantBundleAttacker")
    ).deploy(await executor.getAddress());

    const deadline = BigInt((await time.latest()) + 3600);
    const boundCalls = [
      {
        target: await attacker.getAddress(),
        data: attacker.interface.encodeFunctionData("attack"),
        value: 0n,
        requireSuccess: true,
        approveToken: ZERO,
        approveAmount: 0n,
        gasLimit: 200_000n,
        returnDataLimit: 256n,
      },
    ];
    const trackedAssets = [await token.getAddress()];
    const recipients: string[] = [];
    const intentHash = toFr(
      await executor.intentHashOf(
        boundCalls,
        deadline,
        trackedAssets,
        recipients,
      ),
    );

    const { proof } = await proveWithdrawToExecutor(ctx, 100n, 40n, intentHash);

    const reentrancyError = ethers
      .id("ReentrancyGuardReentrantCall()")
      .slice(0, 10);
    await expect(
      executor.execute(
        proof.proof,
        proof.publicInputs,
        boundCalls,
        deadline,
        trackedAssets,
        recipients,
      ),
    )
      .to.be.revertedWithCustomError(executor, "RequiredCallFailed")
      .withArgs(0, 4, ethers.keccak256(reentrancyError));
  });

  it("preserves a pre-existing donation while settling the bundle", async function () {
    const ctx = await loadFixture(deployExecutorFixture);
    const { darkPool, token, executor, rewardPool } = ctx;
    const asset = await token.getAddress();
    const executorAddress = await executor.getAddress();
    const deadline = BigInt((await time.latest()) + 3600);
    await token.mint(executorAddress, 1n);
    const bundle = buildFeePaymentBundle(
      await domainFor(executor, darkPool),
      asset,
      40n,
      await rewardPool.getAddress(),
      deadline,
      200_000n,
    );
    const { proof } = await proveWithdrawToExecutor(
      ctx,
      100n,
      40n,
      bundle.intentHash,
    );

    await executor.execute(
      proof.proof,
      proof.publicInputs,
      bundle.boundCalls,
      deadline,
      bundle.trackedAssets,
      bundle.recipients,
    );
    expect(await token.balanceOf(executorAddress)).to.equal(1n);
  });

  it("rejects a later attempt to sweep an undeclared donated token", async function () {
    const ctx = await loadFixture(deployExecutorFixture);
    const { token, executor, attacker } = ctx;
    const donatedToken = await (
      await ethers.getContractFactory("MockERC20")
    ).deploy("Donated", "DNT", 18);
    const executorAddress = await executor.getAddress();
    const donatedAsset = await donatedToken.getAddress();
    await donatedToken.mint(executorAddress, 50n);

    const deadline = BigInt((await time.latest()) + 3600);
    const calls: BundleCall[] = [
      {
        target: donatedAsset,
        data: donatedToken.interface.encodeFunctionData("transfer", [
          attacker.address,
          50n,
        ]),
        value: 0n,
        requireSuccess: true,
        approveToken: ZERO,
        approveAmount: 0n,
        gasLimit: 200_000n,
        returnDataLimit: 32n,
      },
    ];
    const trackedAssets = [await token.getAddress()];
    const recipients = [attacker.address];
    const intent = await executor.intentHashOf(
      calls,
      deadline,
      trackedAssets,
      recipients,
    );
    const { proof } = await proveWithdrawToExecutor(
      ctx,
      100n,
      40n,
      toFr(intent),
    );

    await expect(
      executor.execute(
        proof.proof,
        proof.publicInputs,
        calls,
        deadline,
        trackedAssets,
        recipients,
      ),
    )
      .to.be.revertedWithCustomError(executor, "UntrackedTokenCall")
      .withArgs(donatedAsset);
    expect(await donatedToken.balanceOf(executorAddress)).to.equal(50n);
    expect(await donatedToken.balanceOf(attacker.address)).to.equal(0n);
  });

  it("hashes only the signed prefix of huge success and failure return data", async function () {
    const ctx = await loadFixture(deployExecutorFixture);
    const { token, executor, rewardPool, mockTarget } = ctx;
    const asset = await token.getAddress();
    const deadline = BigInt((await time.latest()) + 3600);
    const hugeSize = 65_536n;
    const returnLimit = 32n;
    const emptyPrefixHash = ethers.keccak256(
      new Uint8Array(Number(returnLimit)),
    );
    const calls: BundleCall[] = [
      {
        target: await mockTarget.getAddress(),
        data: new ethers.Interface([
          "function hugeReturn(uint256)",
        ]).encodeFunctionData("hugeReturn", [hugeSize]),
        value: 0n,
        requireSuccess: true,
        approveToken: ZERO,
        approveAmount: 0n,
        gasLimit: 800_000n,
        returnDataLimit: returnLimit,
      },
      {
        target: await mockTarget.getAddress(),
        data: new ethers.Interface([
          "function hugeRevert(uint256)",
        ]).encodeFunctionData("hugeRevert", [hugeSize]),
        value: 0n,
        requireSuccess: false,
        approveToken: ZERO,
        approveAmount: 0n,
        gasLimit: 800_000n,
        returnDataLimit: returnLimit,
      },
      treasuryDepositCall(await rewardPool.getAddress(), asset, 40n, 200_000n),
    ];
    const trackedAssets = [asset];
    const intent = await executor.intentHashOf(
      calls,
      deadline,
      trackedAssets,
      [],
    );
    const { proof } = await proveWithdrawToExecutor(
      ctx,
      100n,
      40n,
      toFr(intent),
    );

    const tx = await executor.execute(
      proof.proof,
      proof.publicInputs,
      calls,
      deadline,
      trackedAssets,
      [],
      { gasLimit: 6_000_000 },
    );
    await expect(tx)
      .to.emit(executor, "CallExecuted")
      .withArgs(0, hugeSize, emptyPrefixHash);
    await expect(tx)
      .to.emit(executor, "CallFailed")
      .withArgs(1, hugeSize, emptyPrefixHash);
  });

  it("contains a target that exhausts its signed gas allowance", async function () {
    const ctx = await loadFixture(deployExecutorFixture);
    const { token, executor, rewardPool, mockTarget } = ctx;
    const asset = await token.getAddress();
    const deadline = BigInt((await time.latest()) + 3600);
    const calls: BundleCall[] = [
      {
        target: await mockTarget.getAddress(),
        data: mockTarget.interface.encodeFunctionData("exhaustGas"),
        value: 0n,
        requireSuccess: false,
        approveToken: ZERO,
        approveAmount: 0n,
        gasLimit: 50_000n,
        returnDataLimit: 32n,
      },
      treasuryDepositCall(await rewardPool.getAddress(), asset, 40n, 200_000n),
    ];
    const trackedAssets = [asset];
    const intent = await executor.intentHashOf(
      calls,
      deadline,
      trackedAssets,
      [],
    );
    const { proof } = await proveWithdrawToExecutor(
      ctx,
      100n,
      40n,
      toFr(intent),
    );

    const tx = await executor.execute(
      proof.proof,
      proof.publicInputs,
      calls,
      deadline,
      trackedAssets,
      [],
    );
    await expect(tx)
      .to.emit(executor, "CallFailed")
      .withArgs(0, 0, ethers.keccak256("0x"));
    await expect(tx).to.emit(rewardPool, "RewardsDeposited");
  });

  it("rejects a BundleExecutor deployment whose DarkPool address has no code", async function () {
    const [deployer] = await ethers.getSigners();
    const factory = await ethers.getContractFactory("BundleExecutor");
    await expect(
      factory.deploy(deployer.address),
    ).to.be.revertedWithCustomError(factory, "DarkPoolHasNoCode");
  });
});
