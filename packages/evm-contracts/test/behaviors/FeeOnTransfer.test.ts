import { expect } from "chai";
import { ethers } from "hardhat";
import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import {
  deployDarkPoolFixture,
  makeDeposit,
  COMPLIANCE_PK,
} from "../helpers/fixtures";
import { toFr, addressToFr, NotePlaintext } from "@hisoka/wallets";
import { proveDeposit } from "@hisoka/prover";

describe("DarkPool Behavior: fee-on-transfer rejection", function () {
  async function deployFoT(feeBps: number) {
    const FoT = await ethers.getContractFactory("MockFeeOnTransferERC20");
    return FoT.deploy("FeeToken", "FEE", 18, feeBps);
  }

  async function buildDepositProof(tokenAddr: string, amount: bigint) {
    const note: NotePlaintext = {
      value: toFr(amount),
      asset_id: addressToFr(tokenAddr),
      secret: toFr(ethers.toBigInt(ethers.randomBytes(31))),
      nullifier: toFr(ethers.toBigInt(ethers.randomBytes(31))),
      timelock: toFr(0n),
      hashlock: toFr(0n),
    };
    return proveDeposit({
      notePlaintext: note,
      ephemeralSk: toFr(12345n),
      compliancePk: COMPLIANCE_PK,
    });
  }

  it("rejects a fee-on-transfer token at deposit", async function () {
    const { darkPool, alice } = await loadFixture(deployDarkPoolFixture);
    const fot = await deployFoT(100); // 1%
    const amount = ethers.parseEther("100");
    await fot.mint(alice.address, amount);
    const proof = await buildDepositProof(await fot.getAddress(), amount);
    await fot.connect(alice).approve(await darkPool.getAddress(), amount);

    await expect(
      darkPool.connect(alice).deposit(proof.proof, proof.publicInputs),
    ).to.be.revertedWithCustomError(darkPool, "FeeOnTransferUnsupported");
  });

  it("still accepts a standard ERC20 deposit", async function () {
    const { darkPool, token, alice } = await loadFixture(deployDarkPoolFixture);
    await makeDeposit(darkPool, token, alice, ethers.parseEther("10"));
  });

  it("rejects a fee-on-transfer token at publicTransfer", async function () {
    const { darkPool, alice } = await loadFixture(deployDarkPoolFixture);
    const fot = await deployFoT(100);
    const amount = ethers.parseEther("50");
    await fot.mint(alice.address, amount);
    await fot.connect(alice).approve(await darkPool.getAddress(), amount);

    await expect(
      darkPool
        .connect(alice)
        .publicTransfer(1n, 2n, await fot.getAddress(), amount, 0n, 12345n),
    ).to.be.revertedWithCustomError(darkPool, "FeeOnTransferUnsupported");
  });
});
