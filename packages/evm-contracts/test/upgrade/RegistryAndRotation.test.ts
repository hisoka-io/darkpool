import { expect } from "chai";
import { ethers } from "hardhat";
import {
  deployDarkPoolFixture,
  makeDeposit,
  mintSelfNote,
  evenYEphemeral,
  userSpendScalar,
  newSeededTree,
  COMPLIANCE_PK,
} from "../helpers/fixtures";
import {
  Fr,
  toFr,
  addressToFr,
  packParents,
  deriveCek,
  computePsi,
  leaf,
  publicKey,
  pubkeyOwner,
  Note,
} from "@hisoka/wallets";
import {
  proveDeposit,
  proveWithdraw,
  WithdrawInputs,
  NoteInput,
} from "@hisoka/prover";
import { Base8, mulPointEscalar, Point } from "@zk-kit/baby-jubjub";

const CIRCUIT_WITHDRAW = 1;

/** Build a self note whose psi wraps to an ARBITRARY compliance key (the fixtures helper hardcodes the
 * deployment key; rotation tests need notes under a rotated key). Mirrors fixtures.finishNote. */
async function buildSelfNoteWithPk(
  eph: Fr,
  value: bigint,
  spendScalar: Fr,
  assetFr: Fr,
  compliancePk: Point<bigint>,
  parents: Fr,
): Promise<{ note: NoteInput; commitment: Fr }> {
  const owner = await pubkeyOwner(publicKey(spendScalar));
  const cek = deriveCek(eph, compliancePk);
  const psi = await computePsi(cek);
  const plaintext: Note = {
    noteVersion: toFr(1n),
    assetId: assetFr,
    noteType: toFr(0n),
    conditionsHash: toFr(0n),
    value,
    owner,
    psi,
    parents,
  };
  const commitment = await leaf(plaintext);
  const note: NoteInput = {
    noteVersion: toFr(1n),
    assetId: assetFr,
    noteType: toFr(0n),
    conditionsHash: toFr(0n),
    value: toFr(value),
    owner,
    psi,
    parents,
  };
  return { note, commitment };
}

describe("Verifier backward-compat + compliance rotation (VR-2, ZK-5)", function () {
  describe("VR-2: identical-VK verifier redeploy", function () {
    it("keeps a pre-existing note spendable after setVerifier swaps in a fresh identical verifier", async function () {
      const ctx = await deployDarkPoolFixture();
      const { darkPool, token, alice } = ctx;
      const assetFr = addressToFr(await token.getAddress());

      const dep = await makeDeposit(darkPool, token, alice, 100n);
      const tree = await newSeededTree();
      await tree.insert(dep.commitment); // index 1

      const oldVerifier = await darkPool.verifier(CIRCUIT_WITHDRAW);
      const fresh = await (
        await ethers.getContractFactory(
          "contracts/verifiers/WithdrawVerifier.sol:HonkVerifier",
        )
      ).deploy();
      await fresh.waitForDeployment();
      const freshAddr = await fresh.getAddress();
      expect(freshAddr).to.not.equal(oldVerifier);

      await darkPool.setVerifier(CIRCUIT_WITHDRAW, freshAddr);
      expect(await darkPool.verifier(CIRCUIT_WITHDRAW)).to.equal(freshAddr);

      const changeEph = evenYEphemeral(1234n);
      const change = await mintSelfNote(
        changeEph,
        60n,
        dep.spendScalar,
        assetFr,
        packParents([{ leafIndex: 1 }, { leafIndex: 0 }]),
      );
      const inputs: WithdrawInputs = {
        withdrawValue: toFr(40n),
        recipient: addressToFr(alice.address),
        intentHash: toFr(0n),
        compliancePk: COMPLIANCE_PK,
        oldNote: dep.built.note,
        spendScalar: dep.spendScalar,
        oldNoteIndex: 1,
        oldNotePath: tree.getMerklePath(1),
        changeNote: change.note,
        changeEph,
      };
      const proof = await proveWithdraw(inputs);

      // The redeployed verifier (identical VK) accepts the pre-existing note: it spends.
      await darkPool.connect(alice).withdraw(proof.proof, proof.publicInputs);
      expect(await darkPool.isNullifierSpent(proof.publicInputs[5])).to.equal(
        true,
      );
    });
  });

  describe("ZK-5: compliance key rotation", function () {
    const NEW_SK = 555777999n;
    const NEW_PK: Point<bigint> = mulPointEscalar(Base8, NEW_SK);

    it("rotates: old-key proof stale, new-key proof accepted, old note still spends, getter updated", async function () {
      const ctx = await deployDarkPoolFixture();
      const { darkPool, token, alice } = ctx;
      const assetFr = addressToFr(await token.getAddress());
      const spendScalar = await userSpendScalar(alice.address);

      // Note minted under the OLD key, before rotation.
      const depOld = await makeDeposit(darkPool, token, alice, 100n);
      const tree = await newSeededTree();
      await tree.insert(depOld.commitment); // leaf 1

      await darkPool.rotateComplianceKey(NEW_PK[0], NEW_PK[1]);

      // (d) getter reflects the new key at version 2.
      const [x, y, version] = await darkPool.complianceKey();
      expect(x).to.equal(NEW_PK[0]);
      expect(y).to.equal(NEW_PK[1]);
      expect(version).to.equal(2n);

      // (a) a proof pinning the OLD key is now stale.
      const staleEph = evenYEphemeral(2001n);
      const staleNote = await buildSelfNoteWithPk(
        staleEph,
        30n,
        spendScalar,
        assetFr,
        COMPLIANCE_PK,
        toFr(0n),
      );
      const staleProof = await proveDeposit({
        compliancePk: COMPLIANCE_PK,
        note: staleNote.note,
        eph: staleEph,
      });
      await expect(darkPool.deposit(staleProof.proof, staleProof.publicInputs))
        .to.be.revertedWithCustomError(darkPool, "ComplianceKeyStale")
        .withArgs(2n, NEW_PK[0], NEW_PK[1]);

      // (c) the OLD note (encrypted to the old key) still spends after rotation; its change note is
      // re-encrypted to the CURRENT (new) key so the on-chain compliance check passes.
      const changeEph = evenYEphemeral(3003n);
      const change = await buildSelfNoteWithPk(
        changeEph,
        60n,
        depOld.spendScalar,
        assetFr,
        NEW_PK,
        packParents([{ leafIndex: 1 }, { leafIndex: 0 }]),
      );
      const wInputs: WithdrawInputs = {
        withdrawValue: toFr(40n),
        recipient: addressToFr(alice.address),
        intentHash: toFr(0n),
        compliancePk: NEW_PK,
        oldNote: depOld.built.note,
        spendScalar: depOld.spendScalar,
        oldNoteIndex: 1,
        oldNotePath: tree.getMerklePath(1),
        changeNote: change.note,
        changeEph,
      };
      const wProof = await proveWithdraw(wInputs);
      await darkPool.connect(alice).withdraw(wProof.proof, wProof.publicInputs);
      expect(await darkPool.isNullifierSpent(wProof.publicInputs[5])).to.equal(
        true,
      );
      await tree.insert(change.commitment); // leaf 2

      // (b) a fresh proof pinning the NEW key is accepted.
      const newEph = evenYEphemeral(4004n);
      const newNote = await buildSelfNoteWithPk(
        newEph,
        30n,
        spendScalar,
        assetFr,
        NEW_PK,
        toFr(0n),
      );
      const newProof = await proveDeposit({
        compliancePk: NEW_PK,
        note: newNote.note,
        eph: newEph,
      });
      await token.connect(alice).approve(await darkPool.getAddress(), 30n);
      const indexBefore = await darkPool.getNextLeafIndex();
      await darkPool
        .connect(alice)
        .deposit(newProof.proof, newProof.publicInputs);
      expect(await darkPool.getNextLeafIndex()).to.equal(indexBefore + 1n);
    });

    it("reverts an off-curve rotation target", async function () {
      const { darkPool } = await deployDarkPoolFixture();
      await expect(
        darkPool.rotateComplianceKey(1n, 1n),
      ).to.be.revertedWithCustomError(darkPool, "InvalidComplianceKeyPoint");
    });

    it("reverts rotating to the identity point (0,1)", async function () {
      const { darkPool } = await deployDarkPoolFixture();
      await expect(
        darkPool.rotateComplianceKey(0n, 1n),
      ).to.be.revertedWithCustomError(darkPool, "InvalidComplianceKeyPoint");
    });

    it("reverts rotation from a non-UPGRADER account", async function () {
      const { darkPool, alice } = await deployDarkPoolFixture();
      await expect(
        darkPool.connect(alice).rotateComplianceKey(NEW_PK[0], NEW_PK[1]),
      ).to.be.revertedWithCustomError(
        darkPool,
        "AccessControlUnauthorizedAccount",
      );
    });
  });
});
