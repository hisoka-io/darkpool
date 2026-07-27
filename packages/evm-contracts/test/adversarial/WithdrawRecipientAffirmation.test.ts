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
import { toFr, addressToFr, packParents } from "@hisoka/wallets";
import { proveWithdraw, WithdrawInputs } from "@hisoka/prover";
import { BundleExecutor__factory } from "../../typechain-types";

const DEPOSIT = 100n;
const WITHDRAW = 40n;

async function deployRecipientsFixture() {
  const base = await deployDarkPoolFixture();

  // Holds no acceptWithdraw and no fallback, so the pool's callback finds nothing to call.
  const silent = await (await ethers.getContractFactory("MockTarget")).deploy();
  const wrongMagic = await (
    await ethers.getContractFactory("WrongMagicRecipient")
  ).deploy();
  const rejecting = await (
    await ethers.getContractFactory("RejectingRecipient")
  ).deploy();

  const dep = await makeDeposit(base.darkPool, base.token, base.alice, DEPOSIT);
  const tree = await newSeededTree();
  await tree.insert(dep.commitment);

  return { ...base, silent, wrongMagic, rejecting, dep, tree };
}

async function proveWithdrawTo(
  ctx: Awaited<ReturnType<typeof deployRecipientsFixture>>,
  recipient: string,
  changeEphSeed: bigint,
) {
  const assetFr = addressToFr(await ctx.token.getAddress());
  const changeEph = evenYEphemeral(changeEphSeed);
  const change = await mintSelfNote(
    changeEph,
    DEPOSIT - WITHDRAW,
    ctx.dep.spendScalar,
    assetFr,
    packParents([{ leafIndex: 1 }, { leafIndex: 0 }]),
  );
  const inputs: WithdrawInputs = {
    withdrawValue: toFr(WITHDRAW),
    recipient: addressToFr(recipient),
    intentHash: toFr(0n),
    compliancePk: COMPLIANCE_PK,
    oldNote: ctx.dep.built.note,
    spendScalar: ctx.dep.spendScalar,
    oldNoteIndex: 1,
    oldNotePath: ctx.tree.getMerklePath(1),
    changeNote: change.note,
    changeEph,
  };
  return proveWithdraw(inputs);
}

describe("Adversarial: contract recipients must affirm their own withdraw", function () {
  this.timeout(600_000);

  it("refuses a recipient that does not implement the interface", async function () {
    const ctx = await loadFixture(deployRecipientsFixture);
    const { darkPool, alice, silent } = ctx;
    const silentAddr = await silent.getAddress();

    const proof = await proveWithdrawTo(ctx, silentAddr, 0xa101n);

    await expect(
      darkPool.connect(alice).withdraw(proof.proof, proof.publicInputs),
    )
      .to.be.revertedWithCustomError(darkPool, "RecipientCannotAcceptWithdraw")
      .withArgs(silentAddr);

    expect(await darkPool.isNullifierSpent(proof.publicInputs[5])).to.equal(
      false,
    );
    expect(await ctx.token.balanceOf(silentAddr)).to.equal(0n);
  });

  it("refuses a recipient that answers with the wrong magic value", async function () {
    const ctx = await loadFixture(deployRecipientsFixture);
    const { darkPool, alice, wrongMagic } = ctx;
    const wrongMagicAddr = await wrongMagic.getAddress();

    const proof = await proveWithdrawTo(ctx, wrongMagicAddr, 0xa102n);

    await expect(
      darkPool.connect(alice).withdraw(proof.proof, proof.publicInputs),
    )
      .to.be.revertedWithCustomError(darkPool, "RecipientRejectedWithdraw")
      .withArgs(wrongMagicAddr);

    expect(await darkPool.isNullifierSpent(proof.publicInputs[5])).to.equal(
      false,
    );
    expect(await ctx.token.balanceOf(wrongMagicAddr)).to.equal(0n);
  });

  it("refuses a recipient that reverts the affirmation", async function () {
    const ctx = await loadFixture(deployRecipientsFixture);
    const { darkPool, alice, rejecting } = ctx;
    const rejectingAddr = await rejecting.getAddress();

    const proof = await proveWithdrawTo(ctx, rejectingAddr, 0xa103n);

    await expect(
      darkPool.connect(alice).withdraw(proof.proof, proof.publicInputs),
    )
      .to.be.revertedWithCustomError(darkPool, "RecipientCannotAcceptWithdraw")
      .withArgs(rejectingAddr);

    expect(await darkPool.isNullifierSpent(proof.publicInputs[5])).to.equal(
      false,
    );
  });

  it("pays an EOA recipient without asking anything", async function () {
    const ctx = await loadFixture(deployRecipientsFixture);
    const { darkPool, token, alice, bob } = ctx;

    const proof = await proveWithdrawTo(ctx, bob.address, 0xa104n);
    const before = await token.balanceOf(bob.address);

    await darkPool.connect(alice).withdraw(proof.proof, proof.publicInputs);

    expect(await token.balanceOf(bob.address)).to.equal(before + WITHDRAW);
  });
});

describe("Adversarial: BundleExecutor affirmation window", function () {
  async function deployProbeFixture() {
    const probe = await (
      await ethers.getContractFactory("PullProbeDarkPool")
    ).deploy();
    const executor = await (
      (await ethers.getContractFactory(
        "BundleExecutor",
      )) as unknown as BundleExecutor__factory
    ).deploy(await probe.getAddress());
    return { probe, executor };
  }

  async function pullArgs(
    executor: Awaited<ReturnType<typeof deployProbeFixture>>["executor"],
  ) {
    const deadline = BigInt((await time.latest()) + 3600);
    const intent = await executor.intentHashOf([], deadline, []);
    const publicInputs = Array(17).fill(ethers.ZeroHash);
    publicInputs[1] = ethers.zeroPadValue(await executor.getAddress(), 32);
    return { deadline, intent, publicInputs };
  }

  it("affirms the pull its own execute opened", async function () {
    const { probe, executor } = await loadFixture(deployProbeFixture);
    const { deadline, intent, publicInputs } = await pullArgs(executor);

    await probe.setProbe(ethers.ZeroHash, intent);

    await expect(
      executor.execute("0x", publicInputs, [], deadline, []),
    ).to.emit(executor, "BundleExecuted");
  });

  it("refuses a second pull raised inside that window on intent mismatch", async function () {
    const { probe, executor } = await loadFixture(deployProbeFixture);
    const { deadline, intent, publicInputs } = await pullArgs(executor);

    await probe.setProbe(ethers.ZeroHash, intent + 1n);

    await expect(
      executor.execute("0x", publicInputs, [], deadline, []),
    ).to.be.revertedWithCustomError(executor, "IntentMismatch");
  });

  it("refuses an affirmation asked for outside any pull", async function () {
    const { executor } = await loadFixture(deployProbeFixture);

    await expect(
      executor.acceptWithdraw(ethers.ZeroHash, 0n),
    ).to.be.revertedWithCustomError(executor, "NotTheDarkPool");
  });
});
