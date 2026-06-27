import { expect } from "chai";
import { ethers } from "hardhat";
import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import { deployDarkPoolFixture } from "../helpers/fixtures";
import { TestWallet } from "../helpers/TestWallet";

describe("DarkPool Behavior: deposit scannability", function () {
  it("discovers self-deposits and reflects them in the balance", async function () {
    const { darkPool, token, alice } = await loadFixture(deployDarkPoolFixture);
    const wallet = await TestWallet.create(alice, darkPool, token);

    const amount = ethers.parseEther("100");
    await wallet.deposit(amount);
    await wallet.sync();

    expect(wallet.getBalance()).to.equal(amount);
    expect(wallet.notes.length).to.equal(1);

    const amount2 = ethers.parseEther("50");
    await wallet.deposit(amount2);
    await wallet.sync();

    expect(wallet.getBalance()).to.equal(amount + amount2);
    expect(wallet.notes.length).to.equal(2);
  });
});
