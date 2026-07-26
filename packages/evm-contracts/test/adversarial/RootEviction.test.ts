/** Every historical root stays known forever (`isKnownRoot` is never cleared), so a proof against an old root still verifies; the nullifier set is the double-spend guard. */
import { expect } from "chai";
import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import {
  deployDarkPoolFixture,
  makeDeposit,
  mintSelfNote,
  evenYEphemeral,
  newSeededTree,
  COMPLIANCE_PK,
} from "../helpers/fixtures";
import { toFr, addressToFr, packParents } from "@hisoka/wallets";
import { proveWithdraw, WithdrawInputs } from "@hisoka/prover";

describe("Adversarial: Merkle root retention (store-all-roots)", function () {
  this.timeout(300_000);

  it("keeps every historical root known after many inserts", async function () {
    const ctx = await loadFixture(deployDarkPoolFixture);
    const { darkPool, token, alice } = ctx;

    const tree = await newSeededTree();
    const roots: string[] = [];

    for (let i = 0; i < 12; i++) {
      const dep = await makeDeposit(darkPool, token, alice, 1n);
      await tree.insert(dep.commitment);
      roots.push(tree.getRoot().toString());
    }

    for (const root of roots) {
      expect(await darkPool.isKnownRoot(root)).to.equal(true);
    }

    expect(await darkPool.getCurrentRoot()).to.equal(roots[roots.length - 1]);
  });

  it("verifies a withdraw against an old, non-current root", async function () {
    const ctx = await loadFixture(deployDarkPoolFixture);
    const { darkPool, token, alice, bob } = ctx;
    const assetFr = addressToFr(await token.getAddress());

    // Capture the root and path before later inserts move the siblings: this root goes stale but stays known.
    const first = await makeDeposit(darkPool, token, alice, 50n);
    const tree = await newSeededTree();
    await tree.insert(first.commitment);
    const staleRoot = tree.getRoot();
    const stalePath = tree.getMerklePath(1);

    for (let i = 0; i < 8; i++) {
      const dep = await makeDeposit(darkPool, token, alice, 1n);
      await tree.insert(dep.commitment);
    }

    expect(await darkPool.getCurrentRoot()).to.not.equal(staleRoot.toString());
    expect(await darkPool.isKnownRoot(staleRoot.toString())).to.equal(true);

    const change = await mintSelfNote(
      evenYEphemeral(999n),
      0n,
      first.spendScalar,
      assetFr,
      packParents([{ leafIndex: 1 }, { leafIndex: 0 }]),
    );
    const wdwInputs: WithdrawInputs = {
      withdrawValue: toFr(50n),
      recipient: addressToFr(bob.address),
      intentHash: toFr(0n),
      compliancePk: COMPLIANCE_PK,
      oldNote: first.built.note,
      spendScalar: first.spendScalar,
      oldNoteIndex: 1,
      oldNotePath: stalePath,
      changeNote: change.note,
      changeEph: change.eph,
    };

    const proof = await proveWithdraw(wdwInputs);
    const balBefore = await token.balanceOf(bob.address);
    await darkPool.withdraw(proof.proof, proof.publicInputs);
    expect(await token.balanceOf(bob.address)).to.equal(balBefore + 50n);
  });
});
