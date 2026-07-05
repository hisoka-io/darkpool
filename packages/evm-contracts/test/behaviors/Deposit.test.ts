import { expect } from "chai";
import { ethers } from "hardhat";
import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import {
  deployDarkPoolFixture,
  makeDeposit,
  mintSelfNote,
  evenYEphemeral,
  userSpendScalar,
  COMPLIANCE_PK,
} from "../helpers/fixtures";
import { addressToFr } from "@hisoka/wallets";
import { proveDeposit } from "@hisoka/prover";

describe("DarkPool Behavior: Deposit", function () {
  it("should allow a valid deposit and emit NewNote", async function () {
    const { darkPool, token, alice } = await loadFixture(deployDarkPoolFixture);
    const amount = 100n;

    const balBefore = await token.balanceOf(await darkPool.getAddress());
    const aliceBalBefore = await token.balanceOf(alice.address);

    await makeDeposit(darkPool, token, alice, amount);

    expect(await token.balanceOf(await darkPool.getAddress())).to.equal(
      balBefore + amount,
    );
    expect(await token.balanceOf(alice.address)).to.equal(
      aliceBalBefore - amount,
    );

    const root = await darkPool.getCurrentRoot();
    expect(await darkPool.isKnownRoot(root)).to.equal(true);
  });

  it("should reject 0 value deposits", async function () {
    const { darkPool, token, alice } = await loadFixture(deployDarkPoolFixture);

    const assetFr = addressToFr(await token.getAddress());
    const eph = evenYEphemeral(101n);
    const spendScalar = await userSpendScalar(alice.address);
    const built = await mintSelfNote(eph, 0n, spendScalar, assetFr);

    const proof = await proveDeposit({
      compliancePk: COMPLIANCE_PK,
      note: built.note,
      eph,
    });

    await expect(
      darkPool.connect(alice).deposit(proof.proof, proof.publicInputs),
    ).to.be.revertedWithCustomError(darkPool, "ValueZero");
  });

  it("should reject incorrect public inputs length", async function () {
    const { darkPool, alice } = await loadFixture(deployDarkPoolFixture);
    await expect(
      darkPool.connect(alice).deposit("0x", []),
    ).to.be.revertedWithCustomError(darkPool, "InvalidInputsLength");
  });

  it("should reject deposit if compliance key in inputs is tampered", async function () {
    const { darkPool, token, alice } = await loadFixture(deployDarkPoolFixture);

    const { proof } = await makeDeposit(darkPool, token, alice, 100n);
    const tamperedInputs = [...proof.publicInputs];
    tamperedInputs[0] = ethers.ZeroHash; // index 0 = compliance X

    await expect(
      darkPool.connect(alice).deposit(proof.proof, tamperedInputs),
    ).to.be.revertedWithCustomError(darkPool, "InvalidComplianceKey");
  });
});
