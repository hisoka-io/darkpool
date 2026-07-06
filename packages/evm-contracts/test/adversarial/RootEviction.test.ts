/**
 * Merkle root retention (store-all-roots).
 *
 * The tree keeps every historical root forever: `isKnownRoot` is never cleared. A proof built against
 * an old, non-current root still verifies; the nullifier set, not root recency, is the double-spend guard.
 * These are regression tests for that invariant (an earlier design evicted all but the last 100 roots).
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

describe("Adversarial: Merkle root retention (store-all-roots)", function () {
  this.timeout(300_000);

  it("keeps every historical root known after many inserts", async function () {
    const ctx = await loadFixture(deployDarkPoolFixture);
    const { darkPool, token, alice } = ctx;

    const tree = new LeanIMT(32);
    const roots: string[] = [];

    for (let i = 0; i < 12; i++) {
      const dep = await makeDeposit(darkPool, token, alice, 1n);
      await tree.insert(dep.commitment);
      roots.push(tree.getRoot().toString());
    }

    // No root is ever evicted: every intermediate root stays known.
    for (const root of roots) {
      expect(await darkPool.isKnownRoot(root)).to.equal(true);
    }

    // getCurrentRoot tracks the latest insert.
    expect(await darkPool.getCurrentRoot()).to.equal(roots[roots.length - 1]);
  });

  it("verifies a withdraw against an old, non-current root", async function () {
    const ctx = await loadFixture(deployDarkPoolFixture);
    const { darkPool, token, alice, bob } = ctx;
    const assetFr = addressToFr(await token.getAddress());

    // First leaf: the note we later spend. Its single-leaf root becomes stale but must stay known.
    const first = await makeDeposit(darkPool, token, alice, 50n);
    const tree = new LeanIMT(32);
    await tree.insert(first.commitment);
    const staleRoot = tree.getRoot();

    for (let i = 0; i < 8; i++) {
      const dep = await makeDeposit(darkPool, token, alice, 1n);
      await tree.insert(dep.commitment);
    }

    // The single-leaf root is no longer current, but retention keeps it known.
    expect(await darkPool.getCurrentRoot()).to.not.equal(staleRoot.toString());
    expect(await darkPool.isKnownRoot(staleRoot.toString())).to.equal(true);

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
    const balBefore = await token.balanceOf(bob.address);
    await darkPool.withdraw(proof.proof, proof.publicInputs);
    expect(await token.balanceOf(bob.address)).to.equal(balBefore + 50n);
  });
});
