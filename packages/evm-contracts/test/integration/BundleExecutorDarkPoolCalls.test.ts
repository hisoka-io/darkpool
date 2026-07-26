import { expect } from "chai";
import { ethers } from "hardhat";
import { loadFixture, time } from "@nomicfoundation/hardhat-network-helpers";
import {
  deployDarkPoolFixture,
  makeDeposit,
  mintSelfNote,
  evenYEphemeral,
  newSeededTree,
  userSpendScalar,
  COMPLIANCE_PK,
} from "../helpers/fixtures";
import { toFr, addressToFr, packParents, Fr } from "@hisoka/wallets";
import { proveWithdraw, proveDeposit, WithdrawInputs } from "@hisoka/prover";
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

async function proveWithdrawTo(
  ctx: Awaited<ReturnType<typeof deployExecutorFixture>>,
  tree: LeanIMT,
  leafIndex: number,
  spendScalar: Fr,
  note: Awaited<ReturnType<typeof makeDeposit>>["built"]["note"],
  depositAmount: bigint,
  withdrawAmount: bigint,
  recipient: string,
  intentHash: Fr,
  changeEphSeed: bigint,
) {
  const assetFr = addressToFr(await ctx.token.getAddress());
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
    recipient: addressToFr(recipient),
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

describe("BundleExecutor: permitted DarkPool calls inside a bundle", function () {
  it("allows a bound deposit that re-shields the withdrawn funds", async function () {
    const ctx = await loadFixture(deployExecutorFixture);
    const { darkPool, token, executor, alice } = ctx;
    const darkPoolAddr = await darkPool.getAddress();
    const tokenAddr = await token.getAddress();
    const executorAddr = await executor.getAddress();
    const VALUE = 1000n;

    const dep = await makeDeposit(darkPool, token, alice, VALUE);
    const tree = await newSeededTree();
    await tree.insert(dep.commitment);

    const reshieldEph = evenYEphemeral(31337n);
    const reshieldBuilt = await mintSelfNote(
      reshieldEph,
      VALUE,
      await userSpendScalar(alice.address),
      addressToFr(tokenAddr),
    );
    const reshield = await proveDeposit({
      compliancePk: COMPLIANCE_PK,
      note: reshieldBuilt.note,
      eph: reshieldEph,
    });

    const deadline = BigInt((await time.latest()) + 3600);
    const calls = [
      {
        target: darkPoolAddr,
        data: darkPool.interface.encodeFunctionData("deposit", [
          reshield.proof,
          reshield.publicInputs,
        ]),
        value: 0n,
        requireSuccess: true,
        approveToken: tokenAddr,
        approveAmount: VALUE,
      },
    ];
    const intent = await executor.intentHashOf(calls, deadline, []);
    const withdrawProof = await proveWithdrawTo(
      ctx,
      tree,
      1,
      dep.spendScalar,
      dep.built.note,
      VALUE,
      VALUE,
      executorAddr,
      toFr(intent),
      4141n,
    );

    await expect(
      executor
        .connect(alice)
        .execute(
          withdrawProof.proof,
          withdrawProof.publicInputs,
          calls,
          deadline,
          [],
        ),
    ).to.emit(darkPool, "Deposited");

    expect(await token.balanceOf(executorAddr)).to.equal(0n);
    expect(
      await darkPool.isNullifierSpent(withdrawProof.publicInputs[5]),
    ).to.equal(true);
  });

  it("allows a bound withdraw naming a third-party recipient", async function () {
    const ctx = await loadFixture(deployExecutorFixture);
    const { darkPool, token, executor, alice, bob } = ctx;
    const darkPoolAddr = await darkPool.getAddress();
    const tokenAddr = await token.getAddress();
    const executorAddr = await executor.getAddress();
    const OUTER = 10n;
    const INNER = 500n;

    const depOuter = await makeDeposit(darkPool, token, alice, OUTER);
    const depInner = await makeDeposit(darkPool, token, alice, INNER);
    const tree = await newSeededTree();
    await tree.insert(depOuter.commitment);
    await tree.insert(depInner.commitment);

    // recipient is an EOA and intentHash is 0: unbound by design, and safe because the pool pays bob directly.
    const innerProof = await proveWithdrawTo(
      ctx,
      tree,
      2,
      depInner.spendScalar,
      depInner.built.note,
      INNER,
      INNER,
      bob.address,
      toFr(0n),
      5151n,
    );

    const deadline = BigInt((await time.latest()) + 3600);
    const calls = [
      {
        target: darkPoolAddr,
        data: darkPool.interface.encodeFunctionData("withdraw", [
          innerProof.proof,
          innerProof.publicInputs,
        ]),
        value: 0n,
        requireSuccess: true,
        approveToken: ZERO,
        approveAmount: 0n,
      },
      {
        target: tokenAddr,
        data: token.interface.encodeFunctionData("transfer", [
          alice.address,
          OUTER,
        ]),
        value: 0n,
        requireSuccess: true,
        approveToken: ZERO,
        approveAmount: 0n,
      },
    ];
    const intent = await executor.intentHashOf(calls, deadline, []);
    const outerProof = await proveWithdrawTo(
      ctx,
      tree,
      1,
      depOuter.spendScalar,
      depOuter.built.note,
      OUTER,
      OUTER,
      executorAddr,
      toFr(intent),
      6161n,
    );

    const bobBefore = await token.balanceOf(bob.address);
    await executor
      .connect(alice)
      .execute(outerProof.proof, outerProof.publicInputs, calls, deadline, []);

    expect(await token.balanceOf(bob.address)).to.equal(bobBefore + INNER);
    expect(await token.balanceOf(executorAddr)).to.equal(0n);
  });
});
