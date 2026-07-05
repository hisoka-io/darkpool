import { expect } from "chai";
import { ethers } from "hardhat";
import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import {
  deployDarkPoolFixture,
  makeDeposit,
  mintSelfNote,
  evenYEphemeral,
  COMPLIANCE_PK,
} from "../helpers/fixtures";
import { toFr, addressToFr, LeanIMT } from "@hisoka/wallets";
import { proveWithdraw, WithdrawInputs } from "@hisoka/prover";

const toBytes32 = (val: bigint) => ethers.zeroPadValue(ethers.toBeHex(val), 32);

describe("DarkPool Behavior: Withdraw", function () {
  async function prepareWithdraw(
    ctx: Awaited<ReturnType<typeof deployDarkPoolFixture>>,
    amount: bigint,
    recipient: string,
  ) {
    const { darkPool, alice, token } = ctx;
    const dep = await makeDeposit(darkPool, token, alice, 100n);

    const tree = new LeanIMT(32);
    await tree.insert(dep.commitment);

    const assetFr = addressToFr(await token.getAddress());
    const changeEph = evenYEphemeral(4242n);
    const change = await mintSelfNote(
      changeEph,
      100n - amount,
      dep.spendScalar,
      assetFr,
    );

    const wdwInputs: WithdrawInputs = {
      withdrawValue: toFr(amount),
      recipient: addressToFr(recipient),
      currentTimestamp: Math.floor(Date.now() / 1000),
      intentHash: toFr(0n),
      compliancePk: COMPLIANCE_PK,
      oldNote: dep.built.note,
      spendScalar: dep.spendScalar,
      oldNoteIndex: 0,
      oldNotePath: Array(32).fill(toFr(0n)),
      changeNote: change.note,
      changeEph,
    };

    const proof = await proveWithdraw(wdwInputs);
    return { proof, inputs: wdwInputs };
  }

  it("should allow valid withdraw", async function () {
    const ctx = await loadFixture(deployDarkPoolFixture);
    const { darkPool, alice, token } = ctx;
    const { proof } = await prepareWithdraw(ctx, 40n, alice.address);

    await darkPool.connect(alice).withdraw(proof.proof, proof.publicInputs);

    expect(await token.balanceOf(alice.address)).to.equal(
      ethers.parseEther("10000") - 100n + 40n,
    );
  });

  it("Should prevent Double Spend", async function () {
    const ctx = await loadFixture(deployDarkPoolFixture);
    const { darkPool, alice } = ctx;
    const { proof } = await prepareWithdraw(ctx, 100n, alice.address);

    await darkPool.connect(alice).withdraw(proof.proof, proof.publicInputs);

    await expect(
      darkPool.connect(alice).withdraw(proof.proof, proof.publicInputs),
    ).to.be.revertedWithCustomError(darkPool, "NullifierAlreadySpent");
  });

  it("Should prevent Front-Running (Recipient Tampering)", async function () {
    const ctx = await loadFixture(deployDarkPoolFixture);
    const { darkPool, alice, attacker } = ctx;
    const { proof } = await prepareWithdraw(ctx, 100n, alice.address);

    // Recipient is public input [1]; rebinding it must break the proof.
    const tamperedInputs = [...proof.publicInputs];
    tamperedInputs[1] = ethers.zeroPadValue(attacker.address, 32);

    await expect(
      darkPool.connect(attacker).withdraw(proof.proof, tamperedInputs),
    ).to.be.reverted;
  });

  it("Should enforce Timestamp Validity", async function () {
    const ctx = await loadFixture(deployDarkPoolFixture);
    const { darkPool, alice } = ctx;
    const { proof } = await prepareWithdraw(ctx, 100n, alice.address);

    // Timestamp is public input [2]; push it ~2h ahead (allowed window is +1h).
    const tamperedInputs = [...proof.publicInputs];
    const futureTime = BigInt(Math.floor(Date.now() / 1000) + 7200);
    tamperedInputs[2] = toBytes32(futureTime);

    await expect(
      darkPool.connect(alice).withdraw(proof.proof, tamperedInputs),
    ).to.be.revertedWithCustomError(darkPool, "TimestampInvalid");
  });
});
