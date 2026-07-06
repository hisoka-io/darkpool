import { expect } from "chai";
import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import {
  deployDarkPoolFixture,
  makeDeposit,
  mintSelfNote,
  mintIncomingNote,
  evenYEphemeral,
  subgroupScalar,
  noteToInput,
  userSpendScalar,
  COMPLIANCE_PK,
} from "../helpers/fixtures";
import { toFr, addressToFr, packParents, LeanIMT, Fr } from "@hisoka/wallets";
import {
  proveWithdraw,
  proveTransfer,
  proveSplit,
  proveJoin,
  provePublicClaim,
  WithdrawInputs,
  TransferInputs,
  SplitInputs,
  JoinInputs,
  PublicClaimInputs,
} from "@hisoka/prover";
import { Base8, mulPointEscalar } from "@zk-kit/baby-jubjub";

// The Honk verifier's NUMBER_OF_PUBLIC_INPUTS counts the caller's inputs plus the appended pairing-point
// accumulator; the contract passes only the former. A wrong split here means the layout table below is
// mis-sized against the on-chain verifier.
const PAIRING_POINTS_SIZE = 8;
const VERIFIER_NUM_PUBLIC_INPUTS: Record<string, number> = {
  deposit: 22,
  withdraw: 27,
  transfer: 35,
  join: 24,
  split: 33,
  publicClaim: 22,
};

function bi(x: string): bigint {
  return BigInt(x);
}

/** Assert `publicInputs[idx]` carries `expected`; distinct expecteds make a symmetric index swap fail here. */
function assertField(
  publicInputs: string[],
  idx: number,
  expected: bigint,
  label: string,
): void {
  expect(bi(publicInputs[idx]!), `${label} @ [${idx}]`).to.equal(expected);
}

describe("Semantic public-input index trace", function () {
  it("deposit: [2] leaf, [3] tag, [5] value, [6] asset", async function () {
    const { darkPool, token, alice } = await loadFixture(deployDarkPoolFixture);
    const asset = addressToFr(await token.getAddress());

    const dep = await makeDeposit(darkPool, token, alice, 123n);
    const pi = dep.proof.publicInputs;

    expect(pi.length).to.equal(
      VERIFIER_NUM_PUBLIC_INPUTS.deposit - PAIRING_POINTS_SIZE,
    );
    assertField(pi, 2, dep.built.commitment.toBigInt(), "leaf");
    assertField(pi, 3, dep.built.tag.toBigInt(), "tag");
    assertField(pi, 5, 123n, "value");
    assertField(pi, 6, asset.toBigInt(), "asset");
  });

  it("withdraw: [0] value, [1] recipient, [6] nullifier, [7] root, [8] asset, [9] change leaf, [10] tag", async function () {
    const { darkPool, token, alice, bob } = await loadFixture(
      deployDarkPoolFixture,
    );
    const asset = addressToFr(await token.getAddress());

    const dep = await makeDeposit(darkPool, token, alice, 100n);
    const tree = new LeanIMT(32);
    await tree.insert(dep.commitment);
    const root = tree.getRoot();

    const spendScalar = await userSpendScalar(alice.address);
    const change = await mintSelfNote(
      evenYEphemeral(4242n),
      60n,
      spendScalar,
      asset,
    );

    const inputs: WithdrawInputs = {
      withdrawValue: toFr(40n),
      recipient: addressToFr(bob.address),
      currentTimestamp: Math.floor(Date.now() / 1000),
      intentHash: toFr(0n),
      compliancePk: COMPLIANCE_PK,
      oldNote: noteToInput(dep.built.note),
      spendScalar: dep.spendScalar,
      oldNoteIndex: 0,
      oldNotePath: tree.getMerklePath(0),
      changeNote: change.note,
      changeEph: change.eph,
    };
    const proof = await proveWithdraw(inputs);
    const pi = proof.publicInputs;

    expect(pi.length).to.equal(
      VERIFIER_NUM_PUBLIC_INPUTS.withdraw - PAIRING_POINTS_SIZE,
    );
    assertField(pi, 0, 40n, "value");
    assertField(pi, 1, addressToFr(bob.address).toBigInt(), "recipient");
    assertField(pi, 7, root.toBigInt(), "root");
    assertField(pi, 8, asset.toBigInt(), "asset");
    assertField(pi, 9, change.commitment.toBigInt(), "change leaf");
    assertField(pi, 10, change.tag.toBigInt(), "tag");
    // Nullifier is circuit-derived; prove [6] is the nullifier by spending and reading it back at [6].
    expect(bi(pi[6]!)).to.not.equal(root.toBigInt());
    expect(bi(pi[6]!)).to.not.equal(change.commitment.toBigInt());
    await darkPool.connect(bob).withdraw(proof.proof, proof.publicInputs);
    expect(await darkPool.isNullifierSpent(pi[6]!)).to.equal(true);
  });

  it("privateTransfer: [3] nullifier, [4] root, [5] memo leaf, [8] tag, [17] change leaf", async function () {
    const { darkPool, token, alice } = await loadFixture(deployDarkPoolFixture);
    const asset = addressToFr(await token.getAddress());

    const dep = await makeDeposit(darkPool, token, alice, 100n);
    const tree = new LeanIMT(32);
    await tree.insert(dep.commitment);
    const root = tree.getRoot();

    const recipientInKey = evenYEphemeral(0x1234n);
    const recipientInPub = mulPointEscalar(Base8, recipientInKey.toBigInt());
    const memoEph = subgroupScalar(0x55aan);
    const memo = await mintIncomingNote(
      memoEph,
      30n,
      recipientInPub,
      toFr(0n),
      asset,
    );

    const spendScalar = await userSpendScalar(alice.address);
    const change = await mintSelfNote(
      evenYEphemeral(7007n),
      70n,
      spendScalar,
      asset,
    );

    const inputs: TransferInputs = {
      currentTimestamp: Math.floor(Date.now() / 1000),
      compliancePk: COMPLIANCE_PK,
      recipientInPub,
      oldNote: noteToInput(dep.built.note),
      spendScalar: dep.spendScalar,
      oldNoteIndex: 0,
      oldNotePath: tree.getMerklePath(0),
      memoNote: memo.note,
      memoEph,
      changeNote: change.note,
      changeEph: change.eph,
    };
    const proof = await proveTransfer(inputs);
    const pi = proof.publicInputs;

    expect(pi.length).to.equal(
      VERIFIER_NUM_PUBLIC_INPUTS.transfer - PAIRING_POINTS_SIZE,
    );
    assertField(pi, 4, root.toBigInt(), "root");
    assertField(pi, 5, memo.commitment.toBigInt(), "memo leaf");
    assertField(pi, 8, new Fr(recipientInPub[0]).toBigInt(), "tag");
    assertField(pi, 17, change.commitment.toBigInt(), "change leaf");
    expect(bi(pi[3]!)).to.not.equal(root.toBigInt());
    expect(bi(pi[3]!)).to.not.equal(memo.commitment.toBigInt());
    await darkPool
      .connect(alice)
      .privateTransfer(proof.proof, proof.publicInputs);
    expect(await darkPool.isNullifierSpent(pi[3]!)).to.equal(true);
  });

  it("join: [3] nullifier_a, [4] nullifier_b, [5] root, [6] out leaf, [7] tag", async function () {
    const { darkPool, token, alice } = await loadFixture(deployDarkPoolFixture);
    const asset = addressToFr(await token.getAddress());

    const depA = await makeDeposit(darkPool, token, alice, 100n);
    const depB = await makeDeposit(darkPool, token, alice, 50n);
    const tree = new LeanIMT(32);
    await tree.insert(depA.commitment);
    await tree.insert(depB.commitment);
    const root = tree.getRoot();

    const out = await mintSelfNote(
      evenYEphemeral(9091n),
      150n,
      depA.spendScalar,
      asset,
      packParents([{ leafIndex: 0 }, { leafIndex: 1 }]),
    );
    const inputs: JoinInputs = {
      currentTimestamp: Math.floor(Date.now() / 1000),
      compliancePk: COMPLIANCE_PK,
      noteA: depA.built.note,
      spendScalarA: depA.spendScalar,
      indexA: 0,
      pathA: tree.getMerklePath(0),
      noteB: depB.built.note,
      spendScalarB: depB.spendScalar,
      indexB: 1,
      pathB: tree.getMerklePath(1),
      noteOut: out.note,
      ephOut: out.eph,
    };
    const proof = await proveJoin(inputs);
    const pi = proof.publicInputs;

    expect(pi.length).to.equal(
      VERIFIER_NUM_PUBLIC_INPUTS.join - PAIRING_POINTS_SIZE,
    );
    assertField(pi, 5, root.toBigInt(), "root");
    assertField(pi, 6, out.commitment.toBigInt(), "out leaf");
    assertField(pi, 7, out.tag.toBigInt(), "tag");
    expect(bi(pi[3]!)).to.not.equal(bi(pi[4]!));
    expect(bi(pi[3]!)).to.not.equal(root.toBigInt());
    await darkPool.connect(alice).join(proof.proof, proof.publicInputs);
    expect(await darkPool.isNullifierSpent(pi[3]!)).to.equal(true);
    expect(await darkPool.isNullifierSpent(pi[4]!)).to.equal(true);
  });

  it("split: [3] nullifier, [4] root, [5] out1 leaf, [6] out1 tag, [15] out2 leaf, [16] out2 tag", async function () {
    const { darkPool, token, alice } = await loadFixture(deployDarkPoolFixture);
    const asset = addressToFr(await token.getAddress());

    const dep = await makeDeposit(darkPool, token, alice, 100n);
    const tree = new LeanIMT(32);
    await tree.insert(dep.commitment);
    const root = tree.getRoot();

    const out1 = await mintSelfNote(
      evenYEphemeral(111n),
      40n,
      dep.spendScalar,
      asset,
    );
    const out2 = await mintSelfNote(
      evenYEphemeral(222n),
      60n,
      dep.spendScalar,
      asset,
    );
    const inputs: SplitInputs = {
      currentTimestamp: Math.floor(Date.now() / 1000),
      compliancePk: COMPLIANCE_PK,
      noteIn: dep.built.note,
      spendScalar: dep.spendScalar,
      indexIn: 0,
      pathIn: tree.getMerklePath(0),
      noteOut1: out1.note,
      eph1: out1.eph,
      noteOut2: out2.note,
      eph2: out2.eph,
    };
    const proof = await proveSplit(inputs);
    const pi = proof.publicInputs;

    expect(pi.length).to.equal(
      VERIFIER_NUM_PUBLIC_INPUTS.split - PAIRING_POINTS_SIZE,
    );
    assertField(pi, 4, root.toBigInt(), "root");
    assertField(pi, 5, out1.commitment.toBigInt(), "out1 leaf");
    assertField(pi, 6, out1.tag.toBigInt(), "out1 tag");
    assertField(pi, 15, out2.commitment.toBigInt(), "out2 leaf");
    assertField(pi, 16, out2.tag.toBigInt(), "out2 tag");
    expect(bi(pi[3]!)).to.not.equal(root.toBigInt());
    await darkPool.connect(alice).split(proof.proof, proof.publicInputs);
    expect(await darkPool.isNullifierSpent(pi[3]!)).to.equal(true);
  });

  it("publicClaim: [0] memoId, [4] out leaf, [5] tag", async function () {
    const { darkPool, token, alice } = await loadFixture(deployDarkPoolFixture);
    const asset = addressToFr(await token.getAddress());

    const recipientSk = subgroupScalar(0xbeefn);
    const recipientPub = mulPointEscalar(Base8, recipientSk.toBigInt());
    const value = 77n;
    const salt = 4242n;

    await token.connect(alice).approve(await darkPool.getAddress(), value);
    const ptTx = await darkPool
      .connect(alice)
      .publicTransfer(
        recipientPub[0],
        recipientPub[1],
        await token.getAddress(),
        value,
        0n,
        salt,
      );
    const ptReceipt = await ptTx.wait();
    const memoLog = ptReceipt!.logs.find(
      (
        l,
      ): l is typeof l & {
        fragment?: { name: string };
        args: { memoId: string };
      } =>
        (l as { fragment?: { name: string } }).fragment?.name ===
        "NewPublicMemo",
    );
    const memoId = (memoLog as unknown as { args: { memoId: string } }).args
      .memoId;

    const outNote = await mintSelfNote(
      evenYEphemeral(3131n),
      value,
      await userSpendScalar(alice.address),
      asset,
    );
    const inputs: PublicClaimInputs = {
      memoId: toFr(memoId),
      compliancePk: COMPLIANCE_PK,
      currentTimestamp: Math.floor(Date.now() / 1000),
      val: toFr(value),
      assetId: asset,
      timelock: toFr(0n),
      ownerX: toFr(recipientPub[0]),
      ownerY: toFr(recipientPub[1]),
      salt: toFr(salt),
      recipientSk,
      noteOut: outNote.note,
      eph: outNote.eph,
    };
    const proof = await provePublicClaim(inputs);
    const pi = proof.publicInputs;

    expect(pi.length).to.equal(
      VERIFIER_NUM_PUBLIC_INPUTS.publicClaim - PAIRING_POINTS_SIZE,
    );
    assertField(pi, 0, bi(memoId), "memoId");
    assertField(pi, 4, outNote.commitment.toBigInt(), "out leaf");
    assertField(pi, 5, outNote.tag.toBigInt(), "tag");
    expect(bi(pi[4]!)).to.not.equal(bi(memoId));
    await darkPool.connect(alice).publicClaim(proof.proof, proof.publicInputs);
    // The memo at [0] is the consumed slot; spending it flips isPublicMemoSpent at exactly that id.
    expect(await darkPool.isPublicMemoSpent(pi[0]!)).to.equal(true);
  });
});
