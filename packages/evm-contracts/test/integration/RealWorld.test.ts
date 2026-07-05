import { expect } from "chai";
import { ethers } from "hardhat";
import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import { deployDarkPoolFixture } from "../helpers/fixtures";
import { TestWallet } from "../helpers/TestWallet";

describe("Integration: The Real World Simulation", function () {
  this.timeout(1200000);

  it("should simulate a multi-hop economy: Alice -> Bob -> Charlie -> Withdraw", async function () {
    const { darkPool, token, alice, bob, charlie } = await loadFixture(
      deployDarkPoolFixture,
    );

    const AMOUNT_DEPOSIT = ethers.parseEther("100");
    const AMOUNT_TRANSFER_1 = ethers.parseEther("50");
    const AMOUNT_TRANSFER_2 = ethers.parseEther("25");
    const INITIAL_BALANCE = ethers.parseEther("10000");

    const aliceWallet = await TestWallet.create(alice, darkPool, token);
    const bobWallet = await TestWallet.create(bob, darkPool, token);
    const charlieWallet = await TestWallet.create(charlie, darkPool, token);

    const depRes = await aliceWallet.deposit(AMOUNT_DEPOSIT);
    await bobWallet.syncTree(depRes.commitment);
    await charlieWallet.syncTree(depRes.commitment);
    await aliceWallet.sync();

    expect(aliceWallet.getBalance()).to.equal(AMOUNT_DEPOSIT);
    expect(await token.balanceOf(alice.address)).to.equal(
      INITIAL_BALANCE - AMOUNT_DEPOSIT,
    );

    const bobAddr = await bobWallet.getReceiveAddress();
    const trf1 = await aliceWallet.transfer(AMOUNT_TRANSFER_1, bobAddr.inPub);

    await bobWallet.syncTree(trf1.memoCommitment);
    await bobWallet.syncTree(trf1.changeCommitment);
    await charlieWallet.syncTree(trf1.memoCommitment);
    await charlieWallet.syncTree(trf1.changeCommitment);

    await bobWallet.sync();
    await aliceWallet.sync();

    expect(aliceWallet.getBalance()).to.equal(
      AMOUNT_DEPOSIT - AMOUNT_TRANSFER_1,
    );
    expect(bobWallet.getBalance()).to.equal(AMOUNT_TRANSFER_1);

    const bobNotes = bobWallet.utxoRepo.getUnspentNotes();
    expect(bobNotes[0].isIncoming).to.equal(true);

    const charlieAddr = await charlieWallet.getReceiveAddress();
    const trf2 = await bobWallet.transfer(AMOUNT_TRANSFER_2, charlieAddr.inPub);

    await aliceWallet.syncTree(trf2.memoCommitment);
    await aliceWallet.syncTree(trf2.changeCommitment);
    await charlieWallet.syncTree(trf2.memoCommitment);
    await charlieWallet.syncTree(trf2.changeCommitment);

    await charlieWallet.sync();
    await bobWallet.sync();

    expect(charlieWallet.getBalance()).to.equal(AMOUNT_TRANSFER_2);
    expect(bobWallet.getBalance()).to.equal(
      AMOUNT_TRANSFER_1 - AMOUNT_TRANSFER_2,
    );

    await charlieWallet.withdraw(AMOUNT_TRANSFER_2);
    await charlieWallet.sync();

    expect(charlieWallet.getBalance()).to.equal(0n);

    const expectedBal = INITIAL_BALANCE + AMOUNT_TRANSFER_2;
    expect(await token.balanceOf(charlie.address)).to.equal(expectedBal);
  });
});
