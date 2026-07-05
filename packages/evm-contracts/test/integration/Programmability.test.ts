import { expect } from "chai";
import { ethers } from "hardhat";
import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import {
  deployDarkPoolFixture,
  makeDeposit,
  mintSelfNote,
  evenYEphemeral,
  COMPLIANCE_PK,
} from "../helpers/fixtures";
import {
  Fr,
  toFr,
  addressToFr,
  deriveCek,
  computePsi,
  pubkeyOwner,
  publicKey,
  LeanIMT,
} from "@hisoka/wallets";
import { proveDeposit, proveWithdraw, NoteInput } from "@hisoka/prover";

// A STANDARD note MUST have note_type == 0 and conditions_hash == 0; the mint circuit rejects
// anything else. These tests pin that invariant.
describe("Integration: Note-type invariants (STANDARD notes)", function () {
  async function nonStandardNote(
    assetFr: Fr,
    overrides: Partial<NoteInput>,
  ): Promise<{ note: NoteInput; eph: Fr }> {
    const eph = evenYEphemeral(7n);
    const cek = deriveCek(eph, COMPLIANCE_PK);
    const psi = await computePsi(cek);
    const owner = await pubkeyOwner(publicKey(toFr(456n)));
    const note: NoteInput = {
      noteVersion: toFr(1n),
      assetId: assetFr,
      noteType: toFr(0n),
      conditionsHash: toFr(0n),
      value: toFr(100n),
      owner,
      psi,
      parents: toFr(0n),
      ...overrides,
    };
    return { note, eph };
  }

  it("rejects a deposit note with a non-zero conditions_hash", async function () {
    const { darkPool, token, alice } = await loadFixture(deployDarkPoolFixture);
    const assetFr = addressToFr(await token.getAddress());
    const { note, eph } = await nonStandardNote(assetFr, {
      conditionsHash: toFr(123n),
    });

    let failed = false;
    try {
      const proof = await proveDeposit({
        compliancePk: COMPLIANCE_PK,
        note,
        eph,
      });
      await darkPool.connect(alice).deposit(proof.proof, proof.publicInputs);
    } catch {
      failed = true;
    }
    expect(failed, "mint must reject a non-zero conditions_hash").to.equal(
      true,
    );
  });

  it("rejects a deposit note with a non-standard note_type", async function () {
    const { darkPool, token, alice } = await loadFixture(deployDarkPoolFixture);
    const assetFr = addressToFr(await token.getAddress());
    const { note, eph } = await nonStandardNote(assetFr, {
      noteType: toFr(1n),
    });

    let failed = false;
    try {
      const proof = await proveDeposit({
        compliancePk: COMPLIANCE_PK,
        note,
        eph,
      });
      await darkPool.connect(alice).deposit(proof.proof, proof.publicInputs);
    } catch {
      failed = true;
    }
    expect(failed, "mint must reject a non-standard note_type").to.equal(true);
  });

  it("re-notes a deposited note to a fresh self note and re-spends it", async function () {
    const { darkPool, token, alice } = await loadFixture(deployDarkPoolFixture);
    const assetFr = addressToFr(await token.getAddress());

    const dep = await makeDeposit(darkPool, token, alice, 100n);
    const tree = new LeanIMT(32);
    await tree.insert(dep.commitment);

    // Withdraw 0: spend the deposit into a fresh self change note (index 1).
    const reNote = await mintSelfNote(
      evenYEphemeral(999n),
      100n,
      dep.spendScalar,
      assetFr,
    );
    const lockProof = await proveWithdraw({
      withdrawValue: toFr(0n),
      recipient: addressToFr(alice.address),
      currentTimestamp: Math.floor(Date.now() / 1000),
      intentHash: toFr(0n),
      compliancePk: COMPLIANCE_PK,
      oldNote: dep.built.note,
      spendScalar: dep.spendScalar,
      oldNoteIndex: 0,
      oldNotePath: Array(32).fill(toFr(0n)),
      changeNote: reNote.note,
      changeEph: reNote.eph,
    });
    await darkPool
      .connect(alice)
      .withdraw(lockProof.proof, lockProof.publicInputs);
    await tree.insert(reNote.commitment);

    // Spend the re-noted note (index 1) fully to Alice.
    const spendPath = Array(32).fill(toFr(0n));
    spendPath[0] = dep.commitment;
    const change = await mintSelfNote(
      evenYEphemeral(1234n),
      0n,
      dep.spendScalar,
      assetFr,
    );
    const spendProof = await proveWithdraw({
      withdrawValue: toFr(100n),
      recipient: addressToFr(alice.address),
      currentTimestamp: Math.floor(Date.now() / 1000),
      intentHash: toFr(0n),
      compliancePk: COMPLIANCE_PK,
      oldNote: reNote.note,
      spendScalar: dep.spendScalar,
      oldNoteIndex: 1,
      oldNotePath: spendPath,
      changeNote: change.note,
      changeEph: change.eph,
    });
    await darkPool
      .connect(alice)
      .withdraw(spendProof.proof, spendProof.publicInputs);

    expect(await token.balanceOf(alice.address)).to.equal(
      ethers.parseEther("10000"),
    );
  });
});
