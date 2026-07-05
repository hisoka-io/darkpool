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

describe("Adversarial: Concurrent Operations", function () {
  this.timeout(120_000);

  it("multiple users deposit simultaneously without state corruption", async function () {
    const ctx = await loadFixture(deployDarkPoolFixture);
    const { darkPool, token, alice, bob, charlie } = ctx;

    const [depA, depB, depC] = await Promise.all([
      makeDeposit(darkPool, token, alice, 100n),
      makeDeposit(darkPool, token, bob, 200n),
      makeDeposit(darkPool, token, charlie, 300n),
    ]);

    const nextIdx = await darkPool.getNextLeafIndex();
    expect(nextIdx).to.equal(3n);

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

    const dep = await makeDeposit(darkPool, token, alice, 100n);
    const tree = new LeanIMT(32);
    await tree.insert(dep.commitment);

    const assetFr = addressToFr(await token.getAddress());
    const change = await mintSelfNote(
      evenYEphemeral(999n),
      50n,
      dep.spendScalar,
      assetFr,
    );

    const wdw: WithdrawInputs = {
      withdrawValue: toFr(50n),
      recipient: addressToFr(bob.address),
      currentTimestamp: Math.floor(Date.now() / 1000),
      intentHash: toFr(0n),
      compliancePk: COMPLIANCE_PK,
      oldNote: dep.built.note,
      spendScalar: dep.spendScalar,
      oldNoteIndex: 0,
      oldNotePath: Array(32).fill(toFr(0n)),
      changeNote: change.note,
      changeEph: change.eph,
    };
    const proof = await proveWithdraw(wdw);
    await darkPool.withdraw(proof.proof, proof.publicInputs);

    await makeDeposit(darkPool, token, bob, 200n);
    const nextIdx = await darkPool.getNextLeafIndex();
    // 1 original + 1 change note + 1 Bob deposit = 3
    expect(nextIdx).to.equal(3n);

    await expect(
      darkPool.withdraw(proof.proof, proof.publicInputs),
    ).to.be.revertedWithCustomError(darkPool, "NullifierAlreadySpent");
  });

  it("sequential deposits maintain correct leaf indices", async function () {
    const ctx = await loadFixture(deployDarkPoolFixture);
    const { darkPool, token, alice } = ctx;

    for (let i = 0; i < 10; i++) {
      await makeDeposit(darkPool, token, alice, BigInt(i + 1));
    }

    const nextIdx = await darkPool.getNextLeafIndex();
    expect(nextIdx).to.equal(10n);
  });
});
