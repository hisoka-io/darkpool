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
import { addressToFr, packParents } from "@hisoka/wallets";
import { proveJoin, JoinInputs, proveSplit, SplitInputs } from "@hisoka/prover";

describe("DarkPool Behavior: Split & Join", function () {
  describe("Join (Merge 2 Notes)", function () {
    it("should merge two notes into one", async function () {
      const { darkPool, token, alice } = await loadFixture(
        deployDarkPoolFixture,
      );
      const assetFr = addressToFr(await token.getAddress());

      const depA = await makeDeposit(darkPool, token, alice, 100n);
      const depB = await makeDeposit(darkPool, token, alice, 50n);

      const tree = await newSeededTree();
      await tree.insert(depA.commitment); // index 1
      await tree.insert(depB.commitment); // index 2

      const out = await mintSelfNote(
        evenYEphemeral(8888n),
        150n,
        depA.spendScalar,
        assetFr,
        packParents([{ leafIndex: 1 }, { leafIndex: 2 }]),
      );

      const inputs: JoinInputs = {
        compliancePk: COMPLIANCE_PK,
        noteA: depA.built.note,
        spendScalarA: depA.spendScalar,
        indexA: 1,
        pathA: tree.getMerklePath(1),
        noteB: depB.built.note,
        spendScalarB: depB.spendScalar,
        indexB: 2,
        pathB: tree.getMerklePath(2),
        noteOut: out.note,
        ephOut: out.eph,
      };

      const proof = await proveJoin(inputs);

      await expect(
        darkPool.connect(alice).join(proof.proof, proof.publicInputs),
      )
        .to.emit(darkPool, "NewNote")
        .and.to.emit(darkPool, "NullifierSpent");

      const nullA = proof.publicInputs[2];
      const nullB = proof.publicInputs[3];
      expect(await darkPool.isNullifierSpent(nullA)).to.equal(true);
      expect(await darkPool.isNullifierSpent(nullB)).to.equal(true);
    });
  });

  describe("Split (Split 1 Note)", function () {
    it("should split one note into two", async function () {
      const { darkPool, token, alice } = await loadFixture(
        deployDarkPoolFixture,
      );
      const assetFr = addressToFr(await token.getAddress());

      const dep = await makeDeposit(darkPool, token, alice, 100n);

      const tree = await newSeededTree();
      await tree.insert(dep.commitment); // index 1

      const outParents = packParents([{ leafIndex: 1 }, { leafIndex: 0 }]);
      const out1 = await mintSelfNote(
        evenYEphemeral(101n),
        40n,
        dep.spendScalar,
        assetFr,
        outParents,
      );
      const out2 = await mintSelfNote(
        evenYEphemeral(202n),
        60n,
        dep.spendScalar,
        assetFr,
        outParents,
      );

      const inputs: SplitInputs = {
        compliancePk: COMPLIANCE_PK,
        noteIn: dep.built.note,
        spendScalar: dep.spendScalar,
        indexIn: 1,
        pathIn: tree.getMerklePath(1),
        noteOut1: out1.note,
        eph1: out1.eph,
        noteOut2: out2.note,
        eph2: out2.eph,
      };

      const proof = await proveSplit(inputs);

      await expect(
        darkPool.connect(alice).split(proof.proof, proof.publicInputs),
      )
        .to.emit(darkPool, "NewNote")
        .and.to.emit(darkPool, "NewNote");

      const nullIn = proof.publicInputs[2];
      expect(await darkPool.isNullifierSpent(nullIn)).to.equal(true);
    });
  });
});
