/**
 * Merkle Root Ring Buffer Eviction Tests
 *
 * DarkPool uses a ring buffer of the last 100 Merkle roots. Proofs referencing
 * an evicted root are rejected (`InvalidRoot`). This tests the eviction boundary.
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

describe("Adversarial: Root Ring Buffer Eviction", function () {
  this.timeout(300_000); // Proof generation + 100+ deposits

  it("root at index 0 is evicted after 101 deposits", async function () {
    const ctx = await loadFixture(deployDarkPoolFixture);
    const { darkPool, token, alice } = ctx;

    const first = await makeDeposit(darkPool, token, alice, 1n);
    const tree = new LeanIMT(32);
    await tree.insert(first.commitment);
    const firstRoot = tree.getRoot();

    expect(await darkPool.isKnownRoot(firstRoot.toString())).to.equal(true);

    // 100 more deposits → 101 total, exceeding the ring buffer of 100
    for (let i = 1; i <= 100; i++) {
      const dep = await makeDeposit(darkPool, token, alice, 1n);
      await tree.insert(dep.commitment);
    }

    // First root is now evicted; latest survives
    expect(await darkPool.isKnownRoot(firstRoot.toString())).to.equal(false);

    const latestRoot = tree.getRoot();
    expect(await darkPool.isKnownRoot(latestRoot.toString())).to.equal(true);
  });

  it("root at index 99 survives exactly 100 deposits", async function () {
    const ctx = await loadFixture(deployDarkPoolFixture);
    const { darkPool, token, alice } = ctx;

    const tree = new LeanIMT(32);

    // 100 deposits — root after the first deposit sits at ring index 0
    const deposits = [];
    for (let i = 0; i < 100; i++) {
      const dep = await makeDeposit(darkPool, token, alice, 1n);
      await tree.insert(dep.commitment);
      deposits.push(dep);
    }

    // The very first root is still valid: only 100 insertions, ring buffer holds 100
    const singleTree = new LeanIMT(32);
    await singleTree.insert(deposits[0]!.commitment);
    const rootAfterFirst = singleTree.getRoot();
    expect(await darkPool.isKnownRoot(rootAfterFirst.toString())).to.equal(
      true,
    );
  });

  it("withdraw with evicted root reverts with InvalidRoot", async function () {
    const ctx = await loadFixture(deployDarkPoolFixture);
    const { darkPool, token, alice, bob } = ctx;

    const first = await makeDeposit(darkPool, token, alice, 50n);
    const tree = new LeanIMT(32);
    await tree.insert(first.commitment);
    const staleRoot = tree.getRoot();

    // 101 more deposits to evict the recorded root
    for (let i = 0; i < 101; i++) {
      const dep = await makeDeposit(darkPool, token, alice, 1n);
      await tree.insert(dep.commitment);
    }

    expect(await darkPool.isKnownRoot(staleRoot.toString())).to.equal(false);

    // Withdrawing against the evicted root must revert
    const wdwInputs: WithdrawInputs = {
      withdrawValue: toFr(50n),
      recipient: addressToFr(bob.address),
      merkleRoot: staleRoot,
      currentTimestamp: Math.floor(Date.now() / 1000),
      intentHash: toFr(0n),
      compliancePk: COMPLIANCE_PK,
      oldNote: first.depositPlain,
      oldSharedSecret: await deriveSharedSecret(
        first.ephemeralSk,
        COMPLIANCE_PK,
      ),
      nk: first.nk,
      oldNoteIndex: 0,
      oldNotePath: Array(32).fill(toFr(0n)),
      hashlockPreimage: toFr(0n),
      changeNote: { ...first.depositPlain, value: toFr(0n) },
      changeEphemeralSk: toFr(999n),
    };

    const proof = await proveWithdraw(wdwInputs);
    await expect(
      darkPool.withdraw(
        proof.proof,
        proof.publicInputs.map((v) => ethers.zeroPadValue(v, 32)),
      ),
    ).to.be.revertedWithCustomError(darkPool, "InvalidRoot");
  });
});
