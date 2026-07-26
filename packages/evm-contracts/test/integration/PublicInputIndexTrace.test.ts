import { expect } from "chai";
import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import {
  deployDarkPoolFixture,
  makeDeposit,
  mintSelfNote,
  mintIncomingNote,
  evenYEphemeral,
  subgroupScalar,
  userSpendScalar,
  newSeededTree,
  COMPLIANCE_PK,
} from "../helpers/fixtures";
import {
  toFr,
  addressToFr,
  packParents,
  PARENTS_HIDDEN,
  computeNullifier,
  Fr,
} from "@hisoka/wallets";
import {
  proveWithdraw,
  proveTransfer,
  proveSplit,
  proveJoin,
  provePublicClaim,
  proveWithdrawMultisig,
  proveTransferMultisig,
  proveSplitMultisig,
  proveJoinMultisig,
  WithdrawInputs,
  TransferInputs,
  SplitInputs,
  JoinInputs,
  PublicClaimInputs,
} from "@hisoka/prover";
import * as frost from "@hisoka/wallets/frost";
import { frostAccountDkg } from "@hisoka/wallets/unsafe-sim";
import {
  buildMultisigNote,
  frostSign,
  depositMultisig,
} from "../helpers/frostMultisig";
import { Base8, mulPointEscalar } from "@zk-kit/baby-jubjub";

// NUMBER_OF_PUBLIC_INPUTS counts the caller's inputs plus the appended pairing-point accumulator; the contract passes only the former.
const PAIRING_POINTS_SIZE = 8;
const VERIFIER_NUM_PUBLIC_INPUTS: Record<string, number> = {
  deposit: 21,
  withdraw: 25,
  transfer: 32,
  join: 22,
  split: 30,
  publicClaim: 21,
  withdrawMultisig: 25,
  transferMultisig: 32,
  splitMultisig: 30,
  joinMultisig: 22,
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
  it("deposit: [2] leaf, [3] tag, [4] value, [5] asset", async function () {
    const { darkPool, token, alice } = await loadFixture(deployDarkPoolFixture);
    const asset = addressToFr(await token.getAddress());

    const dep = await makeDeposit(darkPool, token, alice, 123n);
    const pi = dep.proof.publicInputs;

    expect(pi.length).to.equal(
      VERIFIER_NUM_PUBLIC_INPUTS.deposit - PAIRING_POINTS_SIZE,
    );
    assertField(pi, 2, dep.built.commitment.toBigInt(), "leaf");
    assertField(pi, 3, dep.built.tag.toBigInt(), "tag");
    assertField(pi, 4, 123n, "value");
    assertField(pi, 5, asset.toBigInt(), "asset");
  });

  it("withdraw: [0] value, [1] recipient, [5] nullifier, [6] root, [7] asset, [8] change leaf, [9] tag", async function () {
    const { darkPool, token, alice, bob } = await loadFixture(
      deployDarkPoolFixture,
    );
    const asset = addressToFr(await token.getAddress());

    const dep = await makeDeposit(darkPool, token, alice, 100n);
    const tree = await newSeededTree();
    await tree.insert(dep.commitment);
    const root = tree.getRoot();

    const spendScalar = await userSpendScalar(alice.address);
    const change = await mintSelfNote(
      evenYEphemeral(4242n),
      60n,
      spendScalar,
      asset,
      packParents([{ leafIndex: 1 }, { leafIndex: 0 }]),
    );

    const inputs: WithdrawInputs = {
      withdrawValue: toFr(40n),
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
    const proof = await proveWithdraw(inputs);
    const pi = proof.publicInputs;

    expect(pi.length).to.equal(
      VERIFIER_NUM_PUBLIC_INPUTS.withdraw - PAIRING_POINTS_SIZE,
    );
    assertField(pi, 0, 40n, "value");
    assertField(pi, 1, addressToFr(bob.address).toBigInt(), "recipient");
    assertField(pi, 6, root.toBigInt(), "root");
    assertField(pi, 7, asset.toBigInt(), "asset");
    assertField(pi, 8, change.commitment.toBigInt(), "change leaf");
    assertField(pi, 9, change.tag.toBigInt(), "tag");
    // Nullifier is circuit-derived; prove [5] is the nullifier by spending and reading it back at [5].
    expect(bi(pi[5]!)).to.not.equal(root.toBigInt());
    expect(bi(pi[5]!)).to.not.equal(change.commitment.toBigInt());
    await darkPool.connect(bob).withdraw(proof.proof, proof.publicInputs);
    expect(await darkPool.isNullifierSpent(pi[5]!)).to.equal(true);
  });

  it("privateTransfer: [2] nullifier, [3] root, [4] memo leaf, [6] tag, [15] change leaf", async function () {
    const { darkPool, token, alice } = await loadFixture(deployDarkPoolFixture);
    const asset = addressToFr(await token.getAddress());

    const dep = await makeDeposit(darkPool, token, alice, 100n);
    const tree = await newSeededTree();
    await tree.insert(dep.commitment);
    const root = tree.getRoot();

    const recipientInKey = evenYEphemeral(0x1234n);
    const recipientInPub = mulPointEscalar(Base8, recipientInKey.toBigInt());
    const memoEph = evenYEphemeral(0x55aan);
    const memo = await mintIncomingNote(
      memoEph,
      30n,
      recipientInPub,
      toFr(0n),
      asset,
      PARENTS_HIDDEN,
    );

    const spendScalar = await userSpendScalar(alice.address);
    const change = await mintSelfNote(
      evenYEphemeral(7007n),
      70n,
      spendScalar,
      asset,
      packParents([{ leafIndex: 1 }, { leafIndex: 0 }]),
    );

    const inputs: TransferInputs = {
      compliancePk: COMPLIANCE_PK,
      recipientInPub,
      oldNote: dep.built.note,
      spendScalar: dep.spendScalar,
      oldNoteIndex: 1,
      oldNotePath: tree.getMerklePath(1),
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
    assertField(pi, 3, root.toBigInt(), "root");
    assertField(pi, 4, memo.commitment.toBigInt(), "memo leaf");
    assertField(pi, 6, new Fr(recipientInPub[0]).toBigInt(), "tag");
    assertField(pi, 15, change.commitment.toBigInt(), "change leaf");
    expect(bi(pi[2]!)).to.not.equal(root.toBigInt());
    expect(bi(pi[2]!)).to.not.equal(memo.commitment.toBigInt());
    await darkPool
      .connect(alice)
      .privateTransfer(proof.proof, proof.publicInputs);
    expect(await darkPool.isNullifierSpent(pi[2]!)).to.equal(true);
  });

  it("join: [2] nullifier_a, [3] nullifier_b, [4] root, [5] out leaf, [6] tag", async function () {
    const { darkPool, token, alice } = await loadFixture(deployDarkPoolFixture);
    const asset = addressToFr(await token.getAddress());

    const depA = await makeDeposit(darkPool, token, alice, 100n);
    const depB = await makeDeposit(darkPool, token, alice, 50n);
    const tree = await newSeededTree();
    await tree.insert(depA.commitment);
    await tree.insert(depB.commitment);
    const root = tree.getRoot();

    const out = await mintSelfNote(
      evenYEphemeral(9091n),
      150n,
      depA.spendScalar,
      asset,
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
    const pi = proof.publicInputs;

    expect(pi.length).to.equal(
      VERIFIER_NUM_PUBLIC_INPUTS.join - PAIRING_POINTS_SIZE,
    );
    assertField(pi, 4, root.toBigInt(), "root");
    assertField(pi, 5, out.commitment.toBigInt(), "out leaf");
    assertField(pi, 6, out.tag.toBigInt(), "tag");
    expect(bi(pi[2]!)).to.not.equal(bi(pi[3]!));
    expect(bi(pi[2]!)).to.not.equal(root.toBigInt());
    await darkPool.connect(alice).join(proof.proof, proof.publicInputs);
    expect(await darkPool.isNullifierSpent(pi[2]!)).to.equal(true);
    expect(await darkPool.isNullifierSpent(pi[3]!)).to.equal(true);
  });

  it("split: [2] nullifier, [3] root, [4] out1 leaf, [5] out1 tag, [13] out2 leaf, [14] out2 tag", async function () {
    const { darkPool, token, alice } = await loadFixture(deployDarkPoolFixture);
    const asset = addressToFr(await token.getAddress());

    const dep = await makeDeposit(darkPool, token, alice, 100n);
    const tree = await newSeededTree();
    await tree.insert(dep.commitment);
    const root = tree.getRoot();

    const outParents = packParents([{ leafIndex: 1 }, { leafIndex: 0 }]);
    const out1 = await mintSelfNote(
      evenYEphemeral(111n),
      40n,
      dep.spendScalar,
      asset,
      outParents,
    );
    const out2 = await mintSelfNote(
      evenYEphemeral(222n),
      60n,
      dep.spendScalar,
      asset,
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
    const pi = proof.publicInputs;

    expect(pi.length).to.equal(
      VERIFIER_NUM_PUBLIC_INPUTS.split - PAIRING_POINTS_SIZE,
    );
    assertField(pi, 3, root.toBigInt(), "root");
    assertField(pi, 4, out1.commitment.toBigInt(), "out1 leaf");
    assertField(pi, 5, out1.tag.toBigInt(), "out1 tag");
    assertField(pi, 13, out2.commitment.toBigInt(), "out2 leaf");
    assertField(pi, 14, out2.tag.toBigInt(), "out2 tag");
    expect(bi(pi[2]!)).to.not.equal(root.toBigInt());
    await darkPool.connect(alice).split(proof.proof, proof.publicInputs);
    expect(await darkPool.isNullifierSpent(pi[2]!)).to.equal(true);
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
    expect(await darkPool.isPublicMemoSpent(pi[0]!)).to.equal(true);
  });

  // The 4 multisig twins share the standard op's layout, so a transposition inside a multisig verifier passes both the count-only FreezeSeams check and the mutation-only RealProofE2E binding.
  it("withdrawMultisig: [0] value, [1] recipient, [5] nullifier, [6] root, [7] asset, [8] change leaf, [9] tag", async function () {
    const { darkPool, token, alice, bob } = await loadFixture(
      deployDarkPoolFixture,
    );
    const asset = addressToFr(await token.getAddress());
    const account = await frostAccountDkg(5, 3, 0x54524331n);
    const quorum = account.qual.slice(0, 3);

    const ms = await depositMultisig(
      darkPool,
      token,
      alice,
      100n,
      account.owner,
      asset,
      0x9101n,
    );
    const tree = await newSeededTree();
    await tree.insert(ms.commitment);
    const root = tree.getRoot();
    const nullifier = await computeNullifier(ms.psi, toFr(1n));

    const changeEph = evenYEphemeral(0x9201n);
    const change = await buildMultisigNote(
      changeEph,
      60n,
      account.owner,
      asset,
      packParents([{ leafIndex: 1 }, { leafIndex: 0 }]),
    );
    const m = await frost.msgWithdraw({
      root: root.toBigInt(),
      nullifier: nullifier.toBigInt(),
      changeLeaf: change.commitment.toBigInt(),
      publicOut: 40n,
      asset: asset.toBigInt(),
      recipient: addressToFr(bob.address).toBigInt(),
      intentHash: 0n,
    });
    const { R, z } = await frostSign(account.gpk, account.shares, quorum, m);

    const proof = await proveWithdrawMultisig({
      withdrawValue: toFr(40n),
      recipient: addressToFr(bob.address),
      intentHash: toFr(0n),
      compliancePk: COMPLIANCE_PK,
      gpk: account.gpk,
      frostR: R,
      frostZ: toFr(z),
      oldNote: ms.noteInput,
      oldNoteIndex: 1,
      oldNotePath: tree.getMerklePath(1),
      changeNote: change.noteInput,
      changeEph,
    });
    const pi = proof.publicInputs;

    expect(pi.length).to.equal(
      VERIFIER_NUM_PUBLIC_INPUTS.withdrawMultisig - PAIRING_POINTS_SIZE,
    );
    assertField(pi, 0, 40n, "value");
    assertField(pi, 1, addressToFr(bob.address).toBigInt(), "recipient");
    assertField(pi, 5, nullifier.toBigInt(), "nullifier");
    assertField(pi, 6, root.toBigInt(), "root");
    assertField(pi, 7, asset.toBigInt(), "asset");
    assertField(pi, 8, change.commitment.toBigInt(), "change leaf");
    assertField(pi, 9, change.tag.toBigInt(), "change tag");
    await darkPool
      .connect(alice)
      .withdrawMultisig(proof.proof, proof.publicInputs);
    expect(await darkPool.isNullifierSpent(pi[5]!)).to.equal(true);
  });

  it("transferMultisig: [2] nullifier, [3] root, [4] memo leaf, [6] tag, [15] change leaf", async function () {
    const { darkPool, token, alice } = await loadFixture(deployDarkPoolFixture);
    const asset = addressToFr(await token.getAddress());
    const account = await frostAccountDkg(5, 3, 0x54524332n);
    const quorum = account.qual.slice(0, 3);

    const ms = await depositMultisig(
      darkPool,
      token,
      alice,
      100n,
      account.owner,
      asset,
      0x9102n,
    );
    const tree = await newSeededTree();
    await tree.insert(ms.commitment);
    const root = tree.getRoot();
    const nullifier = await computeNullifier(ms.psi, toFr(1n));

    const recipientInKey = evenYEphemeral(0x556n);
    const recipientInPub = mulPointEscalar(Base8, recipientInKey.toBigInt());
    const memoEph = evenYEphemeral(0x9911n);
    const memo = await mintIncomingNote(
      memoEph,
      40n,
      recipientInPub,
      toFr(0n),
      asset,
      PARENTS_HIDDEN,
    );

    const changeEph = evenYEphemeral(0x9202n);
    const change = await buildMultisigNote(
      changeEph,
      60n,
      account.owner,
      asset,
      packParents([{ leafIndex: 1 }, { leafIndex: 0 }]),
    );
    const m = await frost.msgTransfer({
      root: root.toBigInt(),
      nullifier: nullifier.toBigInt(),
      memoLeaf: memo.commitment.toBigInt(),
      memoTag: recipientInPub[0],
      changeLeaf: change.commitment.toBigInt(),
      asset: asset.toBigInt(),
    });
    const { R, z } = await frostSign(account.gpk, account.shares, quorum, m);

    const proof = await proveTransferMultisig({
      compliancePk: COMPLIANCE_PK,
      gpk: account.gpk,
      frostR: R,
      frostZ: toFr(z),
      recipientInPub,
      oldNote: ms.noteInput,
      oldNoteIndex: 1,
      oldNotePath: tree.getMerklePath(1),
      memoNote: memo.note,
      memoEph: memo.eph,
      changeNote: change.noteInput,
      changeEph,
    });
    const pi = proof.publicInputs;

    expect(pi.length).to.equal(
      VERIFIER_NUM_PUBLIC_INPUTS.transferMultisig - PAIRING_POINTS_SIZE,
    );
    assertField(pi, 2, nullifier.toBigInt(), "nullifier");
    assertField(pi, 3, root.toBigInt(), "root");
    assertField(pi, 4, memo.commitment.toBigInt(), "memo leaf");
    assertField(pi, 6, memo.tag.toBigInt(), "tag");
    assertField(pi, 15, change.commitment.toBigInt(), "change leaf");
    await darkPool
      .connect(alice)
      .transferMultisig(proof.proof, proof.publicInputs);
    expect(await darkPool.isNullifierSpent(pi[2]!)).to.equal(true);
  });

  it("splitMultisig: [2] nullifier, [3] root, [4] out1 leaf, [5] out1 tag, [13] out2 leaf, [14] out2 tag", async function () {
    const { darkPool, token, alice } = await loadFixture(deployDarkPoolFixture);
    const asset = addressToFr(await token.getAddress());
    const account = await frostAccountDkg(5, 3, 0x54524333n);
    const quorum = account.qual.slice(0, 3);

    const ms = await depositMultisig(
      darkPool,
      token,
      alice,
      100n,
      account.owner,
      asset,
      0x9103n,
    );
    const tree = await newSeededTree();
    await tree.insert(ms.commitment);
    const root = tree.getRoot();
    const nullifier = await computeNullifier(ms.psi, toFr(1n));

    const outParents = packParents([{ leafIndex: 1 }, { leafIndex: 0 }]);
    const eph1 = evenYEphemeral(0x9301n);
    // Well separated from eph1: adjacent seeds can round to the same even-y point, which the circuit rejects.
    const eph2 = evenYEphemeral(0x9391n);
    const out1 = await buildMultisigNote(
      eph1,
      40n,
      account.owner,
      asset,
      outParents,
    );
    const out2 = await buildMultisigNote(
      eph2,
      60n,
      account.owner,
      asset,
      outParents,
    );
    const m = await frost.msgSplit({
      root: root.toBigInt(),
      nullifier: nullifier.toBigInt(),
      out1Leaf: out1.commitment.toBigInt(),
      out2Leaf: out2.commitment.toBigInt(),
      asset: asset.toBigInt(),
    });
    const { R, z } = await frostSign(account.gpk, account.shares, quorum, m);

    const proof = await proveSplitMultisig({
      compliancePk: COMPLIANCE_PK,
      gpk: account.gpk,
      frostR: R,
      frostZ: toFr(z),
      noteIn: ms.noteInput,
      indexIn: 1,
      pathIn: tree.getMerklePath(1),
      noteOut1: out1.noteInput,
      eph1,
      noteOut2: out2.noteInput,
      eph2,
    });
    const pi = proof.publicInputs;

    expect(pi.length).to.equal(
      VERIFIER_NUM_PUBLIC_INPUTS.splitMultisig - PAIRING_POINTS_SIZE,
    );
    assertField(pi, 2, nullifier.toBigInt(), "nullifier");
    assertField(pi, 3, root.toBigInt(), "root");
    assertField(pi, 4, out1.commitment.toBigInt(), "out1 leaf");
    assertField(pi, 5, out1.tag.toBigInt(), "out1 tag");
    assertField(pi, 13, out2.commitment.toBigInt(), "out2 leaf");
    assertField(pi, 14, out2.tag.toBigInt(), "out2 tag");
    await darkPool
      .connect(alice)
      .splitMultisig(proof.proof, proof.publicInputs);
    expect(await darkPool.isNullifierSpent(pi[2]!)).to.equal(true);
  });

  it("joinMultisig: [2] nullifier_a, [3] nullifier_b, [4] root, [5] out leaf, [6] out tag", async function () {
    const { darkPool, token, alice } = await loadFixture(deployDarkPoolFixture);
    const asset = addressToFr(await token.getAddress());
    const account = await frostAccountDkg(5, 3, 0x54524334n);
    const quorum = account.qual.slice(0, 3);

    const msA = await depositMultisig(
      darkPool,
      token,
      alice,
      100n,
      account.owner,
      asset,
      0x9104n,
    );
    const msB = await depositMultisig(
      darkPool,
      token,
      alice,
      50n,
      account.owner,
      asset,
      0x9105n,
    );
    const tree = await newSeededTree();
    await tree.insert(msA.commitment);
    await tree.insert(msB.commitment);
    const root = tree.getRoot();
    const nfA = await computeNullifier(msA.psi, toFr(1n));
    const nfB = await computeNullifier(msB.psi, toFr(2n));

    const outEph = evenYEphemeral(0x9401n);
    const out = await buildMultisigNote(
      outEph,
      150n,
      account.owner,
      asset,
      packParents([{ leafIndex: 1 }, { leafIndex: 2 }]),
    );
    const m = await frost.msgJoin({
      root: root.toBigInt(),
      nullifierA: nfA.toBigInt(),
      nullifierB: nfB.toBigInt(),
      outLeaf: out.commitment.toBigInt(),
      asset: asset.toBigInt(),
    });
    const sigA = await frostSign(account.gpk, account.shares, quorum, m);
    const sigB = await frostSign(account.gpk, account.shares, quorum, m);

    const proof = await proveJoinMultisig({
      compliancePk: COMPLIANCE_PK,
      gpkA: account.gpk,
      frostRA: sigA.R,
      frostZA: toFr(sigA.z),
      noteA: msA.noteInput,
      indexA: 1,
      pathA: tree.getMerklePath(1),
      gpkB: account.gpk,
      frostRB: sigB.R,
      frostZB: toFr(sigB.z),
      noteB: msB.noteInput,
      indexB: 2,
      pathB: tree.getMerklePath(2),
      noteOut: out.noteInput,
      ephOut: outEph,
    });
    const pi = proof.publicInputs;

    expect(pi.length).to.equal(
      VERIFIER_NUM_PUBLIC_INPUTS.joinMultisig - PAIRING_POINTS_SIZE,
    );
    assertField(pi, 2, nfA.toBigInt(), "nullifier_a");
    assertField(pi, 3, nfB.toBigInt(), "nullifier_b");
    assertField(pi, 4, root.toBigInt(), "root");
    assertField(pi, 5, out.commitment.toBigInt(), "out leaf");
    assertField(pi, 6, out.tag.toBigInt(), "out tag");
    await darkPool.connect(alice).joinMultisig(proof.proof, proof.publicInputs);
    expect(await darkPool.isNullifierSpent(pi[2]!)).to.equal(true);
    expect(await darkPool.isNullifierSpent(pi[3]!)).to.equal(true);
  });
});
