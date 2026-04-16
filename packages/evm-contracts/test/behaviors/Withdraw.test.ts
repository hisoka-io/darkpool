import { expect } from "chai";
import { ethers } from "hardhat";
import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import {
  deployDarkPoolFixture,
  makeDeposit,
  COMPLIANCE_PK,
} from "../helpers/fixtures";
import {
  toFr,
  addressToFr,
  LeanIMT,
  deriveSharedSecret,
} from "@hisoka/wallets";
import { proveWithdraw, WithdrawInputs } from "@hisoka/prover";

// Helper to pad hex
const toBytes32 = (val: string) => ethers.zeroPadValue(val, 32);

describe("DarkPool Behavior: Withdraw", function () {
  // Helper to generate a valid withdraw proof
  async function prepareWithdraw(
    ctx: Awaited<ReturnType<typeof deployDarkPoolFixture>>,
    amount: bigint,
    recipient: string,
  ) {
    const { darkPool, alice, token } = ctx;
    const {
      depositPlain: realDep,
      ephemeralSk,
      commitment,
    } = await makeDeposit(darkPool, token, alice, 100n);

    // Reconstruct Tree
    const tree = new LeanIMT(32);
    await tree.insert(commitment);

    const wdwInputs: WithdrawInputs = {
      withdrawValue: toFr(amount),
      recipient: addressToFr(recipient),
      merkleRoot: tree.getRoot(),
      currentTimestamp: Math.floor(Date.now() / 1000),
      intentHash: toFr(0n),
      compliancePk: COMPLIANCE_PK,
      oldNote: realDep,
      oldSharedSecret: await deriveSharedSecret(ephemeralSk, COMPLIANCE_PK),
      oldNoteIndex: 0,
      oldNotePath: Array(32).fill(toFr(0n)),
      hashlockPreimage: toFr(0n),
      changeNote: { ...realDep, value: toFr(100n - amount) },
      changeEphemeralSk: toFr(999n),
    };

    const proof = await proveWithdraw(wdwInputs);
    return { proof, inputs: wdwInputs };
  }

  it("should allow valid withdraw", async function () {
    const ctx = await loadFixture(deployDarkPoolFixture);
    const { darkPool, alice, token } = ctx;
    const { proof } = await prepareWithdraw(ctx, 40n, alice.address);

    await darkPool.connect(alice).withdraw(proof.proof, proof.publicInputs);

    // Check balance change (starts with 9900 after deposit, +40 = 9940)
    expect(await token.balanceOf(alice.address)).to.equal(
      ethers.parseEther("10000") - 100n + 40n,
    );
  });

  it("Should prevent Double Spend", async function () {
    const ctx = await loadFixture(deployDarkPoolFixture);
    const { darkPool, alice } = ctx;
    const { proof } = await prepareWithdraw(ctx, 100n, alice.address);

    // First spend ok
    await darkPool.connect(alice).withdraw(proof.proof, proof.publicInputs);

    // Replay
    await expect(
      darkPool.connect(alice).withdraw(proof.proof, proof.publicInputs),
    ).to.be.revertedWithCustomError(darkPool, "NullifierAlreadySpent");
  });

  it("Should prevent Front-Running (Recipient Tampering)", async function () {
    const ctx = await loadFixture(deployDarkPoolFixture);
    const { darkPool, alice, attacker } = ctx;
    const { proof } = await prepareWithdraw(ctx, 100n, alice.address);

    // Attacker intercepts and changes recipient
    const tamperedInputs = [...proof.publicInputs];
    tamperedInputs[1] = toBytes32(attacker.address); // Index 1 is recipient

    await expect(
      darkPool.connect(attacker).withdraw(proof.proof, tamperedInputs),
    ).to.be.reverted; // Verifier rejects
  });

  it("Should enforce Timestamp Validity", async function () {
    // This tests contract-side check: proof timestamp vs block.timestamp
    const ctx = await loadFixture(deployDarkPoolFixture);
    const { darkPool, alice } = ctx;
    const { proof } = await prepareWithdraw(ctx, 100n, alice.address);

    // Tamper with the public input for timestamp (Index 3)
    const tamperedInputs = [...proof.publicInputs];
    // Set timestamp to far future (e.g., now + 2 hours)
    const futureTime = Math.floor(Date.now() / 1000) + 7200;
    tamperedInputs[3] = toBytes32("0x" + BigInt(futureTime).toString());

    // Contract check: require(proofTimestamp <= block.timestamp + 1 hours)
    await expect(
      darkPool.connect(alice).withdraw(proof.proof, tamperedInputs),
    ).to.be.revertedWithCustomError(darkPool, "TimestampInvalid");
  });
});
