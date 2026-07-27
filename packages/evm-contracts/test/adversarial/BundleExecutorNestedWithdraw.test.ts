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
import { BundleExecutor__factory } from "../../typechain-types";
import type { LeanIMT } from "@hisoka/wallets";

const ZERO = "0x0000000000000000000000000000000000000000";

async function deployExecutorFixture() {
  const base = await deployDarkPoolFixture();
  const executor = await (
    (await ethers.getContractFactory(
      "BundleExecutor",
    )) as unknown as BundleExecutor__factory
  ).deploy(await base.darkPool.getAddress());
  return { ...base, executor };
}

async function proveToExecutor(
  ctx: Awaited<ReturnType<typeof deployExecutorFixture>>,
  tree: LeanIMT,
  leafIndex: number,
  spendScalar: Fr,
  note: Awaited<ReturnType<typeof makeDeposit>>["built"]["note"],
  depositAmount: bigint,
  withdrawAmount: bigint,
  intentHash: Fr,
  changeEphSeed: bigint,
) {
  const { token, executor } = ctx;
  const assetFr = addressToFr(await token.getAddress());
  const changeEph = evenYEphemeral(changeEphSeed);
  const change = await mintSelfNote(
    changeEph,
    depositAmount - withdrawAmount,
    spendScalar,
    assetFr,
    packParents([{ leafIndex }, { leafIndex: 0 }]),
  );
  const inputs: WithdrawInputs = {
    withdrawValue: toFr(withdrawAmount),
    recipient: addressToFr(await executor.getAddress()),
    intentHash,
    compliancePk: COMPLIANCE_PK,
    oldNote: note,
    spendScalar,
    oldNoteIndex: leafIndex,
    oldNotePath: tree.getMerklePath(leafIndex),
    changeNote: change.note,
    changeEph,
  };
  return proveWithdraw(inputs);
}

describe("Adversarial: BundleExecutor nested-withdraw confused deputy", function () {
  it("refuses a bound call that re-enters DarkPool.withdraw with a victim's note", async function () {
    const ctx = await loadFixture(deployExecutorFixture);
    const { darkPool, token, executor, alice, attacker, rewardPool } = ctx;
    const executorAddr = await executor.getAddress();
    const darkPoolAddr = await darkPool.getAddress();
    const tokenAddr = await token.getAddress();

    const VICTIM_VALUE = 1000n;
    const DUST = 1n;

    const vDep = await makeDeposit(darkPool, token, alice, VICTIM_VALUE);
    const treeAfterVictim = await newSeededTree();
    await treeAfterVictim.insert(vDep.commitment);

    const deadline = BigInt((await time.latest()) + 3600);
    const victimCalls = [
      {
        target: await rewardPool.getAddress(),
        data: rewardPool.interface.encodeFunctionData("depositRewards", [
          tokenAddr,
          VICTIM_VALUE,
        ]),
        value: 0n,
        requireSuccess: true,
        approveToken: tokenAddr,
        approveAmount: VICTIM_VALUE,
      },
    ];
    const victimIntent = await executor.intentHashOf(victimCalls, deadline, []);
    const victimProof = await proveToExecutor(
      ctx,
      treeAfterVictim,
      1,
      vDep.spendScalar,
      vDep.built.note,
      VICTIM_VALUE,
      VICTIM_VALUE,
      toFr(victimIntent),
      4242n,
    );

    const aDep = await makeDeposit(darkPool, token, attacker, DUST);
    const treeAfterAttacker = await newSeededTree();
    await treeAfterAttacker.insert(vDep.commitment);
    await treeAfterAttacker.insert(aDep.commitment);

    // Bound call 0 re-enters the pool with the victim's UNMODIFIED proof, so nothing upstream of the screen
    // rejects it on its contents.
    const attackerCalls = [
      {
        target: darkPoolAddr,
        data: darkPool.interface.encodeFunctionData("withdraw", [
          victimProof.proof,
          victimProof.publicInputs,
        ]),
        value: 0n,
        requireSuccess: true,
        approveToken: ZERO,
        approveAmount: 0n,
      },
      {
        target: tokenAddr,
        data: token.interface.encodeFunctionData("transfer", [
          attacker.address,
          VICTIM_VALUE + DUST,
        ]),
        value: 0n,
        requireSuccess: true,
        approveToken: ZERO,
        approveAmount: 0n,
      },
    ];
    const attackerIntent = await executor.intentHashOf(
      attackerCalls,
      deadline,
      [],
    );
    const attackerProof = await proveToExecutor(
      ctx,
      treeAfterAttacker,
      2,
      aDep.spendScalar,
      aDep.built.note,
      DUST,
      DUST,
      toFr(attackerIntent),
      777n,
    );

    const attackerBalBefore = await token.balanceOf(attacker.address);

    // The attacker's own proof is valid and verifies; the screen is what stops the theft, not an earlier revert.
    await expect(
      executor
        .connect(attacker)
        .execute(
          attackerProof.proof,
          attackerProof.publicInputs,
          attackerCalls,
          deadline,
          [],
        ),
    )
      .to.be.revertedWithCustomError(executor, "NestedWithdrawToSelf")
      .withArgs(0);

    expect(await token.balanceOf(attacker.address)).to.equal(attackerBalBefore);
    expect(await token.balanceOf(executorAddr)).to.equal(0n);
    expect(
      await darkPool.isNullifierSpent(victimProof.publicInputs[5]),
    ).to.equal(false);

    // The victim's note survives the attempt and their own bundle still executes.
    await executor
      .connect(alice)
      .execute(
        victimProof.proof,
        victimProof.publicInputs,
        victimCalls,
        deadline,
        [],
      );
    expect(await token.balanceOf(executorAddr)).to.equal(0n);
    expect(
      await darkPool.isNullifierSpent(victimProof.publicInputs[5]),
    ).to.equal(true);
  });

  it("refuses an unlisted DarkPool selector in a bound call", async function () {
    const ctx = await loadFixture(deployExecutorFixture);
    const { darkPool, token, executor, attacker } = ctx;
    const darkPoolAddr = await darkPool.getAddress();

    const aDep = await makeDeposit(darkPool, token, attacker, 5n);
    const tree = await newSeededTree();
    await tree.insert(aDep.commitment);

    const deadline = BigInt((await time.latest()) + 3600);
    const joinData = darkPool.interface.encodeFunctionData("join", [
      "0x",
      new Array(24).fill(ethers.ZeroHash),
    ]);
    const calls = [
      {
        target: darkPoolAddr,
        data: joinData,
        value: 0n,
        requireSuccess: true,
        approveToken: ZERO,
        approveAmount: 0n,
      },
    ];
    const intent = await executor.intentHashOf(calls, deadline, []);
    const proof = await proveToExecutor(
      ctx,
      tree,
      1,
      aDep.spendScalar,
      aDep.built.note,
      5n,
      5n,
      toFr(intent),
      888n,
    );

    await expect(
      executor
        .connect(attacker)
        .execute(proof.proof, proof.publicInputs, calls, deadline, []),
    )
      .to.be.revertedWithCustomError(executor, "UnsupportedDarkPoolCall")
      .withArgs(0, joinData.slice(0, 10));
  });

  it("refuses a bound call that grants its own ERC20 allowance", async function () {
    const ctx = await loadFixture(deployExecutorFixture);
    const { darkPool, token, executor, attacker } = ctx;
    const tokenAddr = await token.getAddress();

    const aDep = await makeDeposit(darkPool, token, attacker, 5n);
    const tree = await newSeededTree();
    await tree.insert(aDep.commitment);

    const deadline = BigInt((await time.latest()) + 3600);
    const calls = [
      {
        target: tokenAddr,
        data: token.interface.encodeFunctionData("approve", [
          attacker.address,
          ethers.MaxUint256,
        ]),
        value: 0n,
        requireSuccess: true,
        approveToken: ZERO,
        approveAmount: 0n,
      },
    ];
    const intent = await executor.intentHashOf(calls, deadline, []);
    const proof = await proveToExecutor(
      ctx,
      tree,
      1,
      aDep.spendScalar,
      aDep.built.note,
      5n,
      5n,
      toFr(intent),
      999n,
    );

    await expect(
      executor
        .connect(attacker)
        .execute(proof.proof, proof.publicInputs, calls, deadline, []),
    )
      .to.be.revertedWithCustomError(executor, "AllowanceCallForbidden")
      .withArgs(0);

    expect(
      await token.allowance(await executor.getAddress(), attacker.address),
    ).to.equal(0n);
  });
});
