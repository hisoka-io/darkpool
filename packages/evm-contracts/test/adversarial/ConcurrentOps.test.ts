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
import { toFr, addressToFr, packParents, Fr } from "@hisoka/wallets";
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
    // genesis leaf at index 0 + three deposits.
    expect(nextIdx).to.equal(4n);

    // Deposits land concurrently, so the on-chain insertion order need not match
    // the submission order; rebuild the local tree in actual leaf-index order.
    const noteEvents = await darkPool.queryFilter(darkPool.filters.NewNote());
    const leafIndexOf = (commitment: Fr): number => {
      const ev = noteEvents.find((e) =>
        toFr(e.args.commitment).equals(commitment),
      );
      if (!ev)
        throw new Error("deposit commitment missing from NewNote events");
      return Number(ev.args.leafIndex);
    };
    const tree = await newSeededTree();
    for (const dep of [depA, depB, depC].sort(
      (a, b) => leafIndexOf(a.commitment) - leafIndexOf(b.commitment),
    )) {
      await tree.insert(dep.commitment);
    }
    expect(await darkPool.isKnownRoot(tree.getRoot().toString())).to.equal(
      true,
    );
  });

  it("deposit + withdraw interleaved: no double-spend", async function () {
    const ctx = await loadFixture(deployDarkPoolFixture);
    const { darkPool, token, alice, bob } = ctx;

    const dep = await makeDeposit(darkPool, token, alice, 100n);
    const tree = await newSeededTree();
    await tree.insert(dep.commitment);

    const assetFr = addressToFr(await token.getAddress());
    const change = await mintSelfNote(
      evenYEphemeral(999n),
      50n,
      dep.spendScalar,
      assetFr,
      packParents([{ leafIndex: 1 }, { leafIndex: 0 }]),
    );

    const wdw: WithdrawInputs = {
      withdrawValue: toFr(50n),
      recipient: addressToFr(bob.address),
      intentHash: toFr(0n),
      compliancePk: COMPLIANCE_PK,
      oldNote: dep.built.note,
      spendScalar: dep.spendScalar,
      oldNoteIndex: 1,
      oldNotePath: tree.getMerklePath(1),
      changeNote: change.note,
      changeEph: change.eph,
    };
    const proof = await proveWithdraw(wdw);
    await darkPool.withdraw(proof.proof, proof.publicInputs);

    await makeDeposit(darkPool, token, bob, 200n);
    const nextIdx = await darkPool.getNextLeafIndex();
    // genesis + 1 original + 1 change note + 1 Bob deposit = 4
    expect(nextIdx).to.equal(4n);

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
    // genesis leaf at index 0 + ten deposits.
    expect(nextIdx).to.equal(11n);
  });
});
