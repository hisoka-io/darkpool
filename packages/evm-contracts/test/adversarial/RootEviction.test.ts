/**
 * Merkle Root Ring Buffer Eviction Tests
 *
 * DarkPool uses a ring buffer of the last 100 Merkle roots. Proofs referencing an evicted root are
 * rejected (`InvalidRoot`). This tests the eviction boundary.
 */
import { expect } from "chai";
import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import {
  deployDarkPoolFixture,
  makeDeposit,
  mintSelfNote,
  evenYEphemeral,
  COMPLIANCE_PK,
} from "../helpers/fixtures";
import { toFr, addressToFr, LeanIMT } from "@hisoka/wallets";
import { proveWithdraw, WithdrawInputs } from "@hisoka/prover";

describe("Adversarial: Root Ring Buffer Eviction", function () {
  this.timeout(300_000);

  it("root at index 0 is evicted after 101 deposits", async function () {
    const ctx = await loadFixture(deployDarkPoolFixture);
    const { darkPool, token, alice } = ctx;

    const first = await makeDeposit(darkPool, token, alice, 1n);
    const tree = new LeanIMT(32);
    await tree.insert(first.commitment);
    const firstRoot = tree.getRoot();

    expect(await darkPool.isKnownRoot(firstRoot.toString())).to.equal(true);

    for (let i = 1; i <= 100; i++) {
      const dep = await makeDeposit(darkPool, token, alice, 1n);
      await tree.insert(dep.commitment);
    }

    expect(await darkPool.isKnownRoot(firstRoot.toString())).to.equal(false);

    const latestRoot = tree.getRoot();
    expect(await darkPool.isKnownRoot(latestRoot.toString())).to.equal(true);
  });

  it("root at index 99 survives exactly 100 deposits", async function () {
    const ctx = await loadFixture(deployDarkPoolFixture);
    const { darkPool, token, alice } = ctx;

    const tree = new LeanIMT(32);

    const deposits = [];
    for (let i = 0; i < 100; i++) {
      const dep = await makeDeposit(darkPool, token, alice, 1n);
      await tree.insert(dep.commitment);
      deposits.push(dep);
    }

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
    const assetFr = addressToFr(await token.getAddress());

    const first = await makeDeposit(darkPool, token, alice, 50n);
    const tree = new LeanIMT(32);
    await tree.insert(first.commitment);
    const staleRoot = tree.getRoot();

    for (let i = 0; i < 101; i++) {
      const dep = await makeDeposit(darkPool, token, alice, 1n);
      await tree.insert(dep.commitment);
    }

    expect(await darkPool.isKnownRoot(staleRoot.toString())).to.equal(false);

    // Proving membership at index 0 with an all-zero path outputs the single-leaf (stale) root.
    const change = await mintSelfNote(
      evenYEphemeral(999n),
      0n,
      first.spendScalar,
      assetFr,
    );
    const wdwInputs: WithdrawInputs = {
      withdrawValue: toFr(50n),
      recipient: addressToFr(bob.address),
      currentTimestamp: Math.floor(Date.now() / 1000),
      intentHash: toFr(0n),
      compliancePk: COMPLIANCE_PK,
      oldNote: first.built.note,
      spendScalar: first.spendScalar,
      oldNoteIndex: 0,
      oldNotePath: Array(32).fill(toFr(0n)),
      changeNote: change.note,
      changeEph: change.eph,
    };

    const proof = await proveWithdraw(wdwInputs);
    await expect(
      darkPool.withdraw(proof.proof, proof.publicInputs),
    ).to.be.revertedWithCustomError(darkPool, "InvalidRoot");
  });
});
