import { expect } from "chai";
import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import {
  deployDarkPoolFixture,
  makeDeposit,
  COMPLIANCE_PK,
} from "../helpers/fixtures";
import {
  toFr,
  LeanIMT,
  deriveSharedSecret,
  NotePlaintext,
} from "@hisoka/wallets";
import { proveJoin, JoinInputs, proveSplit, SplitInputs } from "@hisoka/prover";

describe("DarkPool Behavior: Split & Join", function () {
  describe("Join (Merge 2 Notes)", function () {
    it("should merge two notes into one", async function () {
      const { darkPool, token, alice } = await loadFixture(
        deployDarkPoolFixture,
      );

      const depA = await makeDeposit(darkPool, token, alice, 100n);
      const depB = await makeDeposit(darkPool, token, alice, 50n);
      const nk = depA.nk;

      const tree = new LeanIMT(32);
      await tree.insert(depA.commitment); // index 0 = A
      await tree.insert(depB.commitment); // index 1 = B
      const root = tree.getRoot();

      // Path for A (0): sibling is B
      const pathA = Array(32).fill(toFr(0n));
      pathA[0] = depB.commitment;

      // Path for B (1): sibling is A
      const pathB = Array(32).fill(toFr(0n));
      pathB[0] = depA.commitment;

      const noteOut: NotePlaintext = {
        ...depA.depositPlain,
        value: toFr(150n),
        secret: toFr(8888n),
      };

      const inputs: JoinInputs = {
        merkleRoot: root,
        currentTimestamp: Math.floor(Date.now() / 1000),
        compliancePk: COMPLIANCE_PK,

        noteA: depA.depositPlain,
        secretA: await deriveSharedSecret(depA.ephemeralSk, COMPLIANCE_PK),
        indexA: 0,
        pathA: pathA,
        preimageA: toFr(0n),

        noteB: depB.depositPlain,
        secretB: await deriveSharedSecret(depB.ephemeralSk, COMPLIANCE_PK),
        indexB: 1,
        pathB: pathB,
        preimageB: toFr(0n),

        nk,

        noteOut: noteOut,
        skOut: toFr(777n),
      };

      const proof = await proveJoin(inputs);

      await expect(
        darkPool.connect(alice).join(proof.proof, proof.publicInputs),
      )
        .to.emit(darkPool, "NewNote")
        .and.to.emit(darkPool, "NullifierSpent");

      const nullA = proof.publicInputs[4];
      const nullB = proof.publicInputs[5];
      expect(await darkPool.isNullifierSpent(nullA)).to.equal(true);
      expect(await darkPool.isNullifierSpent(nullB)).to.equal(true);
    });
  });

  describe("Split (Split 1 Note)", function () {
    it("should split one note into two", async function () {
      const { darkPool, token, alice } = await loadFixture(
        deployDarkPoolFixture,
      );

      const dep = await makeDeposit(darkPool, token, alice, 100n);

      const tree = new LeanIMT(32);
      await tree.insert(dep.commitment);

      // Outputs: 40 + 60
      const out1: NotePlaintext = {
        ...dep.depositPlain,
        value: toFr(40n),
      };
      const out2: NotePlaintext = {
        ...dep.depositPlain,
        value: toFr(60n),
      };

      const inputs: SplitInputs = {
        merkleRoot: tree.getRoot(),
        currentTimestamp: Math.floor(Date.now() / 1000),
        compliancePk: COMPLIANCE_PK,

        noteIn: dep.depositPlain,
        secretIn: await deriveSharedSecret(dep.ephemeralSk, COMPLIANCE_PK),
        indexIn: 0,
        pathIn: Array(32).fill(toFr(0n)),
        preimageIn: toFr(0n),

        nk: dep.nk,

        noteOut1: out1,
        skOut1: toFr(101n),
        noteOut2: out2,
        skOut2: toFr(102n),
      };

      const proof = await proveSplit(inputs);

      await expect(
        darkPool.connect(alice).split(proof.proof, proof.publicInputs),
      )
        .to.emit(darkPool, "NewNote")
        .and.to.emit(darkPool, "NewNote");

      const nullIn = proof.publicInputs[4];
      expect(await darkPool.isNullifierSpent(nullIn)).to.equal(true);
    });
  });
});
