import { expect } from "chai";
import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import {
  deployDarkPoolFixture,
  makeDeposit,
  mintSelfNote,
  mintIncomingNote,
  evenYEphemeral,
  subgroupScalar,
  COMPLIANCE_PK,
  COMPLIANCE_SK,
} from "../helpers/fixtures";
import {
  Fr,
  toFr,
  addressToFr,
  publicKey,
  deriveCek,
  demDecrypt,
} from "@hisoka/wallets";
import { proveTransfer, TransferInputs } from "@hisoka/prover";
import { Point } from "@zk-kit/baby-jubjub";

const ZERO_PATH = () => Array(32).fill(toFr(0n));

describe("DarkPool Behavior: Private Transfer", function () {
  it("should execute a valid transfer from Alice to Bob", async function () {
    const { darkPool, token, alice } = await loadFixture(deployDarkPoolFixture);
    const assetFr = addressToFr(await token.getAddress());

    const dep = await makeDeposit(darkPool, token, alice, 100n);

    // Bob publishes an even-y incoming address; Alice encrypts the memo to it.
    const bobInKey = evenYEphemeral(555n);
    const bobInPub = publicKey(bobInKey);

    const memo = await mintIncomingNote(
      subgroupScalar(12345n),
      40n,
      bobInPub,
      bobInKey,
      assetFr,
    );
    const change = await mintSelfNote(
      evenYEphemeral(67890n),
      60n,
      dep.spendScalar,
      assetFr,
    );

    const inputs: TransferInputs = {
      currentTimestamp: Math.floor(Date.now() / 1000),
      compliancePk: COMPLIANCE_PK,
      recipientInPub: bobInPub,
      oldNote: dep.built.note,
      spendScalar: dep.spendScalar,
      oldNoteIndex: 0,
      oldNotePath: ZERO_PATH(),
      memoNote: memo.note,
      memoEph: memo.eph,
      changeNote: change.note,
      changeEph: change.eph,
    };

    const proof = await proveTransfer(inputs);

    await expect(
      darkPool.connect(alice).privateTransfer(proof.proof, proof.publicInputs),
    )
      .to.emit(darkPool, "NewPrivateMemo")
      .and.to.emit(darkPool, "NewNote")
      .and.to.emit(darkPool, "NullifierSpent");

    // Nullifier is public input [3] in the v2 transfer layout.
    const nullifierHash = proof.publicInputs[3];
    expect(await darkPool.isNullifierSpent(nullifierHash)).to.equal(true);
  });

  it("Should prevent Double Transfer", async function () {
    const { darkPool, token, alice } = await loadFixture(deployDarkPoolFixture);
    const assetFr = addressToFr(await token.getAddress());
    const dep = await makeDeposit(darkPool, token, alice, 100n);

    const bobInKey = evenYEphemeral(123n);
    const bobInPub = publicKey(bobInKey);

    const memo = await mintIncomingNote(
      subgroupScalar(1n),
      50n,
      bobInPub,
      bobInKey,
      assetFr,
    );
    const change = await mintSelfNote(
      evenYEphemeral(2n),
      50n,
      dep.spendScalar,
      assetFr,
    );

    const inputs: TransferInputs = {
      currentTimestamp: Math.floor(Date.now() / 1000),
      compliancePk: COMPLIANCE_PK,
      recipientInPub: bobInPub,
      oldNote: dep.built.note,
      spendScalar: dep.spendScalar,
      oldNoteIndex: 0,
      oldNotePath: ZERO_PATH(),
      memoNote: memo.note,
      memoEph: memo.eph,
      changeNote: change.note,
      changeEph: change.eph,
    };

    const proof = await proveTransfer(inputs);
    await darkPool
      .connect(alice)
      .privateTransfer(proof.proof, proof.publicInputs);

    await expect(
      darkPool.connect(alice).privateTransfer(proof.proof, proof.publicInputs),
    ).to.be.revertedWithCustomError(darkPool, "NullifierAlreadySpent");
  });

  it("PRIV-1: two rotated payments to one recipient share no on-chain linkable field, and compliance still decrypts both", async function () {
    const { darkPool, token, alice } = await loadFixture(deployDarkPoolFixture);
    const assetFr = addressToFr(await token.getAddress());

    // Unlinkability requires the recipient to rotate incoming addresses: each payment targets a distinct
    // even-y in_pub_j, so the on-chain tag (= in_pub_j.x) differs across payments.
    async function transferToBob(
      inKeySeed: bigint,
      memoEph: bigint,
      changeEph: bigint,
    ): Promise<string[]> {
      const bobInKey = evenYEphemeral(inKeySeed);
      const bobInPub = publicKey(bobInKey);
      const dep = await makeDeposit(darkPool, token, alice, 100n);
      const memo = await mintIncomingNote(
        subgroupScalar(memoEph),
        40n,
        bobInPub,
        bobInKey,
        assetFr,
      );
      const change = await mintSelfNote(
        evenYEphemeral(changeEph),
        60n,
        dep.spendScalar,
        assetFr,
      );
      const inputs: TransferInputs = {
        currentTimestamp: Math.floor(Date.now() / 1000),
        compliancePk: COMPLIANCE_PK,
        recipientInPub: bobInPub,
        oldNote: dep.built.note,
        spendScalar: dep.spendScalar,
        oldNoteIndex: 0,
        oldNotePath: ZERO_PATH(),
        memoNote: memo.note,
        memoEph: memo.eph,
        changeNote: change.note,
        changeEph: change.eph,
      };
      return (await proveTransfer(inputs)).publicInputs;
    }

    const p1 = await transferToBob(555n, 11111n, 22222n);
    const p2 = await transferToBob(777n, 33333n, 44444n);

    const norm = (x: string): string => toFr(x).toString();
    expect(p1.length).to.equal(27);
    expect(p2.length).to.equal(27);

    // Past the protocol-public prefix [0..2] (ts, compliance x/y) and root [4], no value repeats across
    // the two payments: nullifier, memo/change leaves, ephemerals, tag, cek_wrap, ciphertexts are fresh.
    const tail1 = new Set(p1.slice(5).map(norm));
    const shared = p2
      .slice(5)
      .map(norm)
      .filter((v) => tail1.has(v));
    expect(shared).to.deep.equal([]);

    // Compliance decrypts each memo structurally: CEK = (complianceSk * eph_pub).x, ciphertext at [10..16].
    for (const pub of [p1, p2]) {
      const fr = pub.map((s) => toFr(s));
      const ephPub: Point<bigint> = [fr[6].toBigInt(), fr[7].toBigInt()];
      const cek = deriveCek(new Fr(COMPLIANCE_SK), ephPub);
      const plaintext = await demDecrypt(cek, fr.slice(10, 17));
      expect(plaintext[4].equals(toFr(40n))).to.equal(true);
    }
  });
});
