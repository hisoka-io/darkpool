import { expect } from "chai";
import { ethers } from "hardhat";
import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import { deployDarkPoolFixture } from "../helpers/fixtures";
import { TestWallet } from "../helpers/TestWallet";
import { publicKey } from "@hisoka/wallets";
import { EventLog } from "ethers";

describe("DarkPool Behavior: Public Interop", function () {
  it("should allow Public Transfer -> Public Claim -> Private Withdraw", async function () {
    const { darkPool, token, alice, bob } = await loadFixture(
      deployDarkPoolFixture,
    );

    const bobWallet = await TestWallet.create(bob, darkPool, token);
    const AMOUNT = ethers.parseEther("50");

    // Bob's claim key: a subgroup scalar he controls; its public key is the memo owner (ownerX/ownerY).
    const bobClaimSk = await bobWallet.account.getIncomingKey(0n);
    const bobClaimPub = publicKey(bobClaimSk);

    await token.connect(alice).approve(await darkPool.getAddress(), AMOUNT);

    const salt = 12345n;
    const tx = await darkPool
      .connect(alice)
      .publicTransfer(
        bobClaimPub[0],
        bobClaimPub[1],
        await token.getAddress(),
        AMOUNT,
        0,
        salt,
      );
    const receipt = await tx.wait();

    const log = receipt!.logs.find(
      (l) => (l as EventLog).fragment?.name === "NewPublicMemo",
    );
    const args = (log as EventLog).args;

    expect(args.value).to.equal(AMOUNT);
    expect(await darkPool.isValidPublicMemo(args.memoId)).to.equal(true);
    expect(await darkPool.isPublicMemoSpent(args.memoId)).to.equal(false);

    await bobWallet.claimPublic(
      {
        memoId: args.memoId,
        ownerX: bobClaimPub[0],
        ownerY: bobClaimPub[1],
        asset: args.asset,
        value: args.value,
        timelock: args.timelock,
        salt: args.salt,
      },
      bobClaimSk,
    );
    await bobWallet.sync();

    expect(await darkPool.isPublicMemoSpent(args.memoId)).to.equal(true);
    expect(bobWallet.getBalance()).to.equal(AMOUNT);

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

    const bobClaimSk = await bobWallet.account.getIncomingKey(0n);
    const bobClaimPub = publicKey(bobClaimSk);

    await token.connect(alice).approve(await darkPool.getAddress(), AMOUNT);
    const tx = await darkPool
      .connect(alice)
      .publicTransfer(
        bobClaimPub[0],
        bobClaimPub[1],
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

    const claimArgs = {
      memoId: args.memoId,
      ownerX: bobClaimPub[0],
      ownerY: bobClaimPub[1],
      asset: args.asset,
      value: args.value,
      timelock: args.timelock,
      salt: args.salt,
    };

    await bobWallet.claimPublic(claimArgs, bobClaimSk);

    await expect(
      bobWallet.claimPublic(claimArgs, bobClaimSk),
    ).to.be.revertedWithCustomError(darkPool, "MemoSpent");
  });
});
