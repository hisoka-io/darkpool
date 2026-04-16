/**
 * Concurrent Operations Tests
 *
 * Verifies DarkPool handles multiple users performing deposits, withdrawals,
 * and transfers concurrently without state corruption.
 */
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

describe("Adversarial: Concurrent Operations", function () {
  this.timeout(120_000);

  it("multiple users deposit simultaneously without state corruption", async function () {
    const ctx = await loadFixture(deployDarkPoolFixture);
    const { darkPool, token, alice, bob, charlie } = ctx;

    // All three users deposit in quick succession
    const [depA, depB, depC] = await Promise.all([
      makeDeposit(darkPool, token, alice, 100n),
      makeDeposit(darkPool, token, bob, 200n),
      makeDeposit(darkPool, token, charlie, 300n),
    ]);

    // Verify all three notes were created (nextLeafIndex should be 3)
    const nextIdx = await darkPool.getNextLeafIndex();
    expect(nextIdx).to.equal(3n);

    // Verify all roots are valid
    const tree = new LeanIMT(32);
    await tree.insert(depA.commitment);
    await tree.insert(depB.commitment);
    await tree.insert(depC.commitment);
    expect(await darkPool.isKnownRoot(tree.getRoot().toString())).to.equal(
      true,
    );
  });

  it("deposit + withdraw interleaved: no double-spend", async function () {
    const ctx = await loadFixture(deployDarkPoolFixture);
    const { darkPool, token, alice, bob } = ctx;

    // Alice deposits 100
    const dep = await makeDeposit(darkPool, token, alice, 100n);
    const tree = new LeanIMT(32);
    await tree.insert(dep.commitment);

    // Alice withdraws 50
    const wdw: WithdrawInputs = {
      withdrawValue: toFr(50n),
      recipient: addressToFr(bob.address),
      merkleRoot: tree.getRoot(),
      currentTimestamp: Math.floor(Date.now() / 1000),
      intentHash: toFr(0n),
      compliancePk: COMPLIANCE_PK,
      oldNote: dep.depositPlain,
      oldSharedSecret: await deriveSharedSecret(dep.ephemeralSk, COMPLIANCE_PK),
      oldNoteIndex: 0,
      oldNotePath: Array(32).fill(toFr(0n)),
      hashlockPreimage: toFr(0n),
      changeNote: { ...dep.depositPlain, value: toFr(50n) },
      changeEphemeralSk: toFr(999n),
    };
    const proof = await proveWithdraw(wdw);
    await darkPool.withdraw(
      proof.proof,
      proof.publicInputs.map((v) => ethers.zeroPadValue(v, 32)),
    );

    // Bob deposits 200 AFTER Alice's withdrawal (tree state has changed)
    await makeDeposit(darkPool, token, bob, 200n);
    const nextIdx = await darkPool.getNextLeafIndex();
    // 1 original + 1 change note + 1 Bob deposit = 3
    expect(nextIdx).to.equal(3n);

    // Trying to re-use Alice's nullifier should fail
    await expect(
      darkPool.withdraw(
        proof.proof,
        proof.publicInputs.map((v) => ethers.zeroPadValue(v, 32)),
      ),
    ).to.be.revertedWithCustomError(darkPool, "NullifierAlreadySpent");
  });

  it("sequential deposits maintain correct leaf indices", async function () {
    const ctx = await loadFixture(deployDarkPoolFixture);
    const { darkPool, token, alice } = ctx;

    // 10 sequential deposits
    for (let i = 0; i < 10; i++) {
      await makeDeposit(darkPool, token, alice, BigInt(i + 1));
    }

    const nextIdx = await darkPool.getNextLeafIndex();
    expect(nextIdx).to.equal(10n);
  });
});
