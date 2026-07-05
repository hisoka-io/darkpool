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

      const tree = new LeanIMT(32);
      await tree.insert(depA.commitment); // index 0
      await tree.insert(depB.commitment); // index 1

      const pathA = Array(32).fill(toFr(0n));
      pathA[0] = depB.commitment;
      const pathB = Array(32).fill(toFr(0n));
      pathB[0] = depA.commitment;

      const out = await mintSelfNote(
        evenYEphemeral(8888n),
        150n,
        depA.spendScalar,
        assetFr,
      );

      const inputs: JoinInputs = {
        currentTimestamp: Math.floor(Date.now() / 1000),
        compliancePk: COMPLIANCE_PK,
        noteA: depA.built.note,
        spendScalarA: depA.spendScalar,
        indexA: 0,
        pathA,
        noteB: depB.built.note,
        spendScalarB: depB.spendScalar,
        indexB: 1,
        pathB,
        noteOut: out.note,
        ephOut: out.eph,
      };

      const proof = await proveJoin(inputs);

      await expect(darkPool.connect(alice).join(proof.proof, proof.publicInputs))
        .to.emit(darkPool, "NewNote")
        .and.to.emit(darkPool, "NullifierSpent");

      const nullA = proof.publicInputs[3];
      const nullB = proof.publicInputs[4];
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

      const out1 = await mintSelfNote(
        evenYEphemeral(101n),
        40n,
        dep.spendScalar,
        assetFr,
      );
      const out2 = await mintSelfNote(
        evenYEphemeral(202n),
        60n,
        dep.spendScalar,
        assetFr,
      );

      const inputs: SplitInputs = {
        currentTimestamp: Math.floor(Date.now() / 1000),
        compliancePk: COMPLIANCE_PK,
        noteIn: dep.built.note,
        spendScalar: dep.spendScalar,
        indexIn: 0,
        pathIn: Array(32).fill(toFr(0n)),
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

      const nullIn = proof.publicInputs[3];
      expect(await darkPool.isNullifierSpent(nullIn)).to.equal(true);
    });
  });
});
