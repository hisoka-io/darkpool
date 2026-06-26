import { expect } from "chai";
import { ethers } from "hardhat";
import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import { deployDarkPoolFixture } from "../helpers/fixtures";
import { TestWallet } from "../helpers/TestWallet";
import { EventLog } from "ethers";

describe("DarkPool Behavior: Public Interop", function () {
  it("should allow Public Transfer -> Public Claim -> Private Withdraw", async function () {
    const { darkPool, token, alice, bob } = await loadFixture(
      deployDarkPoolFixture,
    );

    const bobWallet = await TestWallet.create(bob, darkPool, token);
    const AMOUNT = ethers.parseEther("50");

    // --- 1. PUBLIC TRANSFER (Alice -> Bob) ---
    // Alice is a public EOA (no wallet/proof needed); she only needs Bob's derived public key.
    await bobWallet.keyRepo.advanceIncomingKeys(1);
    const bobSk = await bobWallet.account.getIncomingViewingKey(0n);
    const bobPk = await bobWallet.account.getPublicIncomingViewingKey(0n);

    await token.connect(alice).approve(await darkPool.getAddress(), AMOUNT);

    const salt = 12345n;
    const tx = await darkPool.connect(alice).publicTransfer(
      bobPk[0],
      bobPk[1],
      await token.getAddress(),
      AMOUNT,
      0, // No timelock
      salt,
    );
    const receipt = await tx.wait();

    // NewPublicMemo(memoId, ownerX, ownerY, asset, value, timelock, salt)
    const log = receipt!.logs.find(
      (l) => (l as EventLog).fragment?.name === "NewPublicMemo",
    );
    const args = (log as EventLog).args;

    expect(args.value).to.equal(AMOUNT);

    expect(await darkPool.isValidPublicMemo(args.memoId)).to.equal(true);
    expect(await darkPool.isPublicMemoSpent(args.memoId)).to.equal(false);

    // --- 2. PUBLIC CLAIM (Bob claims into his shielded wallet) ---
    console.log("Generating Public Claim Proof...");
    await bobWallet.claimPublic(
      {
        memoId: args.memoId,
        ownerX: args.ownerX,
        ownerY: args.ownerY,
        asset: args.asset,
        value: args.value,
        timelock: args.timelock,
        salt: args.salt,
      },
      bobSk,
    );

    expect(await darkPool.isPublicMemoSpent(args.memoId)).to.equal(true);
    expect(bobWallet.getBalance()).to.equal(AMOUNT);

    // --- 3. PRIVATE WITHDRAW (Bob) — proves the claimed note is spendable ---
    console.log("Withdrawing claimed funds...");
    await bobWallet.withdraw(AMOUNT);

    expect(await token.balanceOf(bob.address)).to.equal(
      ethers.parseEther("10000") + AMOUNT,
    );
  });

  it("should fail to claim a spent memo", async function () {
    const { darkPool, token, alice, bob } = await loadFixture(
      deployDarkPoolFixture,
    );
    const bobWallet = await TestWallet.create(bob, darkPool, token);
    const AMOUNT = ethers.parseEther("10");

    // Setup: create and claim once, then attempt a replay
    await bobWallet.keyRepo.advanceIncomingKeys(1);
    const bobSk = await bobWallet.account.getIncomingViewingKey(0n);
    const bobPk = await bobWallet.account.getPublicIncomingViewingKey(0n);

    await token.connect(alice).approve(await darkPool.getAddress(), AMOUNT);
    const tx = await darkPool
      .connect(alice)
      .publicTransfer(
        bobPk[0],
        bobPk[1],
        await token.getAddress(),
        AMOUNT,
        0,
        999n,
      );
    const receipt = await tx.wait();
    const args = (
      receipt!.logs.find(
        (l) => (l as EventLog).fragment?.name === "NewPublicMemo",
      ) as EventLog
    ).args;

    await bobWallet.claimPublic(
      {
        memoId: args.memoId,
        ownerX: args.ownerX,
        ownerY: args.ownerY,
        asset: args.asset,
        value: args.value,
        timelock: args.timelock,
        salt: args.salt,
      },
      bobSk,
    );

    await expect(
      bobWallet.claimPublic(
        {
          memoId: args.memoId,
          ownerX: args.ownerX,
          ownerY: args.ownerY,
          asset: args.asset,
          value: args.value,
          timelock: args.timelock,
          salt: args.salt,
        },
        bobSk,
      ),
    ).to.be.revertedWithCustomError(darkPool, "MemoSpent");
  });
});
