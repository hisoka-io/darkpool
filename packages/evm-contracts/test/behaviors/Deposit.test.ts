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

describe("DarkPool Behavior: Deposit", function () {
  it("should allow a valid deposit and emit NewNote", async function () {
    const { darkPool, token, alice } = await loadFixture(deployDarkPoolFixture);
    const amount = 100n;

    // We capture the receipt to check events
    const balBefore = await token.balanceOf(await darkPool.getAddress());
    const aliceBalBefore = await token.balanceOf(alice.address);

    await makeDeposit(darkPool, token, alice, amount);

    // Check Balances (use delta to avoid parallel test interference)
    expect(await token.balanceOf(await darkPool.getAddress())).to.equal(
      balBefore + amount,
    );
    expect(await token.balanceOf(alice.address)).to.equal(
      aliceBalBefore - amount,
    );

    // Check Root update
    const root = await darkPool.getCurrentRoot();
    expect(await darkPool.isKnownRoot(root)).to.equal(true);
  });

  it("should reject 0 value deposits", async function () {
    const { darkPool, token, alice } = await loadFixture(deployDarkPoolFixture);

    // Create inputs for 0 value (circuit might allow it, but contract should block it)
    const assetFr = addressToFr(await token.getAddress());
    const note: NotePlaintext = {
      value: toFr(0n),
      asset_id: assetFr,
      secret: toFr(1n),
      nullifier: toFr(2n),
      timelock: toFr(0n),
      hashlock: toFr(0n),
    };
    const ephSk = toFr(123n);
    const proof = await proveDeposit({
      notePlaintext: note,
      ephemeralSk: ephSk,
      compliancePk: COMPLIANCE_PK,
    });

    await expect(
      darkPool.connect(alice).deposit(proof.proof, proof.publicInputs),
    ).to.be.revertedWithCustomError(darkPool, "ValueZero");
  });

  it("should reject incorrect public inputs length", async function () {
    const { darkPool, alice } = await loadFixture(deployDarkPoolFixture);
    await expect(darkPool.connect(alice).deposit("0x", [])).to.be.revertedWithCustomError(
      darkPool,
      "InvalidInputsLength",
    );
  });

  it("should reject deposit if compliance key in inputs is tampered", async function () {
    const { darkPool, token, alice } = await loadFixture(deployDarkPoolFixture);

    const { proof } = await makeDeposit(darkPool, token, alice, 100n);
    const tamperedInputs = [...proof.publicInputs];
    tamperedInputs[0] = ethers.ZeroHash; // Corrupt Compliance X

    await expect(
      darkPool.connect(alice).deposit(proof.proof, tamperedInputs),
    ).to.be.revertedWithCustomError(darkPool, "InvalidComplianceKey");
  });
});
