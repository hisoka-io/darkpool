import { loadFixture, time } from "@nomicfoundation/hardhat-network-helpers";
import {
  deployDarkPoolFixture,
  makeDeposit,
  mintSelfNote,
  mintIncomingNote,
  evenYEphemeral,
  subgroupScalar,
  userSpendScalar,
  newSeededTree,
  noteToInput,
  COMPLIANCE_PK,
} from "../helpers/fixtures";
import {
  buildMultisigNote,
  frostSign,
  depositMultisig,
} from "../helpers/frostMultisig";
import {
  toFr,
  addressToFr,
  packParents,
  publicKey,
  computeNullifier,
} from "@hisoka/wallets";
import * as frost from "@hisoka/wallets/frost";
import { frostAccountDkg } from "@hisoka/wallets/unsafe-sim";
import {
  proveDeposit,
  proveWithdraw,
  proveTransfer,
  proveSplit,
  proveJoin,
  provePublicClaim,
  proveWithdrawMultisig,
  proveTransferMultisig,
  proveSplitMultisig,
  proveJoinMultisig,
} from "@hisoka/prover";
import { Base8, mulPointEscalar } from "@zk-kit/baby-jubjub";

// Standalone: never part of test:fast (its dir is outside the fast globs) and additionally env-gated so a bare
// `hardhat test` skips it. Run once with: GAS_BENCH=1 npx hardhat test test/benchmark/Gas.bench.ts
const run = process.env.GAS_BENCH ? describe : describe.skip;

const results: { op: string; gas: bigint }[] = [];
function record(op: string, gas: bigint | undefined) {
  results.push({ op, gas: gas ?? 0n });
}

run("Benchmark: per-entrypoint gas", function () {
  this.timeout(1_200_000);

  after(function () {
    const rows = results
      .map((r) => `| ${r.op.padEnd(19)} | ${r.gas.toString().padStart(9)} |`)
      .join("\n");
    console.log(
      `\n## Per-entrypoint gas (gasUsed from the on-chain submit receipt)\n` +
        `| entrypoint          |   gasUsed |\n` +
        `|---------------------|-----------|\n${rows}\n`,
    );
  });

  it("deposit", async function () {
    const { darkPool, token, alice } = await loadFixture(deployDarkPoolFixture);
    const assetFr = addressToFr(await token.getAddress());
    const spendScalar = await userSpendScalar(alice.address);
    const eph = evenYEphemeral(101n);
    const built = await mintSelfNote(eph, 100n, spendScalar, assetFr);
    const proof = await proveDeposit({
      compliancePk: COMPLIANCE_PK,
      note: built.note,
      eph,
    });
    await token.connect(alice).approve(await darkPool.getAddress(), 100n);
    const receipt = await (
      await darkPool.connect(alice).deposit(proof.proof, proof.publicInputs)
    ).wait();
    record("deposit", receipt?.gasUsed);
  });

  it("withdraw", async function () {
    const { darkPool, token, alice, bob } = await loadFixture(
      deployDarkPoolFixture,
    );
    const assetFr = addressToFr(await token.getAddress());
    const dep = await makeDeposit(darkPool, token, alice, 100n);
    const tree = await newSeededTree();
    await tree.insert(dep.commitment);
    const change = await mintSelfNote(
      evenYEphemeral(4242n),
      60n,
      dep.spendScalar,
      assetFr,
      packParents([{ leafIndex: 1 }, { leafIndex: 0 }]),
    );
    const proof = await proveWithdraw({
      withdrawValue: toFr(40n),
      recipient: addressToFr(bob.address),
      intentHash: toFr(0n),
      compliancePk: COMPLIANCE_PK,
      oldNote: noteToInput(dep.built.note),
      spendScalar: dep.spendScalar,
      oldNoteIndex: 1,
      oldNotePath: tree.getMerklePath(1),
      changeNote: change.note,
      changeEph: change.eph,
    });
    const receipt = await (
      await darkPool.connect(alice).withdraw(proof.proof, proof.publicInputs)
    ).wait();
    record("withdraw", receipt?.gasUsed);
  });

  it("transfer", async function () {
    const { darkPool, token, alice } = await loadFixture(deployDarkPoolFixture);
    const assetFr = addressToFr(await token.getAddress());
    const dep = await makeDeposit(darkPool, token, alice, 100n);
    const tree = await newSeededTree();
    await tree.insert(dep.commitment);
    const bobInKey = evenYEphemeral(555n);
    const bobInPub = publicKey(bobInKey);
    const parents = packParents([{ leafIndex: 1 }, { leafIndex: 0 }]);
    const memo = await mintIncomingNote(
      subgroupScalar(12345n),
      40n,
      bobInPub,
      bobInKey,
      assetFr,
      parents,
    );
    const change = await mintSelfNote(
      evenYEphemeral(67890n),
      60n,
      dep.spendScalar,
      assetFr,
      parents,
    );
    const proof = await proveTransfer({
      compliancePk: COMPLIANCE_PK,
      recipientInPub: bobInPub,
      oldNote: noteToInput(dep.built.note),
      spendScalar: dep.spendScalar,
      oldNoteIndex: 1,
      oldNotePath: tree.getMerklePath(1),
      memoNote: memo.note,
      memoEph: memo.eph,
      changeNote: change.note,
      changeEph: change.eph,
    });
    const receipt = await (
      await darkPool
        .connect(alice)
        .privateTransfer(proof.proof, proof.publicInputs)
    ).wait();
    record("transfer", receipt?.gasUsed);
  });

  it("split", async function () {
    const { darkPool, token, alice } = await loadFixture(deployDarkPoolFixture);
    const assetFr = addressToFr(await token.getAddress());
    const dep = await makeDeposit(darkPool, token, alice, 100n);
    const tree = await newSeededTree();
    await tree.insert(dep.commitment);
    const outParents = packParents([{ leafIndex: 1 }, { leafIndex: 0 }]);
    const out1 = await mintSelfNote(
      evenYEphemeral(111n),
      40n,
      dep.spendScalar,
      assetFr,
      outParents,
    );
    const out2 = await mintSelfNote(
      evenYEphemeral(222n),
      60n,
      dep.spendScalar,
      assetFr,
      outParents,
    );
    const proof = await proveSplit({
      compliancePk: COMPLIANCE_PK,
      noteIn: noteToInput(dep.built.note),
      spendScalar: dep.spendScalar,
      indexIn: 1,
      pathIn: tree.getMerklePath(1),
      noteOut1: out1.note,
      eph1: out1.eph,
      noteOut2: out2.note,
      eph2: out2.eph,
    });
    const receipt = await (
      await darkPool.connect(alice).split(proof.proof, proof.publicInputs)
    ).wait();
    record("split", receipt?.gasUsed);
  });

  it("join", async function () {
    const { darkPool, token, alice } = await loadFixture(deployDarkPoolFixture);
    const assetFr = addressToFr(await token.getAddress());
    const depA = await makeDeposit(darkPool, token, alice, 100n);
    const depB = await makeDeposit(darkPool, token, alice, 50n);
    const tree = await newSeededTree();
    await tree.insert(depA.commitment);
    await tree.insert(depB.commitment);
    const out = await mintSelfNote(
      evenYEphemeral(9091n),
      150n,
      depA.spendScalar,
      assetFr,
      packParents([{ leafIndex: 1 }, { leafIndex: 2 }]),
    );
    const proof = await proveJoin({
      compliancePk: COMPLIANCE_PK,
      noteA: noteToInput(depA.built.note),
      spendScalarA: depA.spendScalar,
      indexA: 1,
      pathA: tree.getMerklePath(1),
      noteB: noteToInput(depB.built.note),
      spendScalarB: depB.spendScalar,
      indexB: 2,
      pathB: tree.getMerklePath(2),
      noteOut: out.note,
      ephOut: out.eph,
    });
    const receipt = await (
      await darkPool.connect(alice).join(proof.proof, proof.publicInputs)
    ).wait();
    record("join", receipt?.gasUsed);
  });

  it("publicClaim", async function () {
    const { darkPool, token, alice } = await loadFixture(deployDarkPoolFixture);
    const assetFr = addressToFr(await token.getAddress());
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
      assetFr,
    );
    const proof = await provePublicClaim({
      memoId: toFr(memoId),
      compliancePk: COMPLIANCE_PK,
      currentTimestamp: await time.latest(),
      val: toFr(value),
      assetId: assetFr,
      timelock: toFr(0n),
      ownerX: toFr(recipientPub[0]),
      ownerY: toFr(recipientPub[1]),
      salt: toFr(salt),
      recipientSk,
      noteOut: outNote.note,
      eph: outNote.eph,
    });
    const receipt = await (
      await darkPool.connect(alice).publicClaim(proof.proof, proof.publicInputs)
    ).wait();
    record("publicClaim", receipt?.gasUsed);
  });

  it("withdrawMultisig", async function () {
    const { darkPool, token, alice, bob } = await loadFixture(
      deployDarkPoolFixture,
    );
    const assetFr = addressToFr(await token.getAddress());
    const account = await frostAccountDkg(5, 3, 0x484f574c01n);
    const quorum = account.qual.slice(0, 3);
    const ms = await depositMultisig(
      darkPool,
      token,
      alice,
      100n,
      account.owner,
      assetFr,
      11n,
    );
    const tree = await newSeededTree();
    await tree.insert(ms.commitment);
    const nullifier = await computeNullifier(ms.psi, toFr(1n));
    const changeEph = evenYEphemeral(2201n);
    const change = await buildMultisigNote(
      changeEph,
      60n,
      account.owner,
      assetFr,
      packParents([{ leafIndex: 1 }, { leafIndex: 0 }]),
    );
    const m = await frost.msgWithdraw({
      root: tree.getRoot().toBigInt(),
      nullifier: nullifier.toBigInt(),
      changeLeaf: change.commitment.toBigInt(),
      publicOut: 40n,
      asset: assetFr.toBigInt(),
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
    const receipt = await (
      await darkPool
        .connect(alice)
        .withdrawMultisig(proof.proof, proof.publicInputs)
    ).wait();
    record("withdrawMultisig", receipt?.gasUsed);
  });

  it("transferMultisig", async function () {
    const { darkPool, token, alice } = await loadFixture(deployDarkPoolFixture);
    const assetFr = addressToFr(await token.getAddress());
    const account = await frostAccountDkg(5, 3, 0x484f574c02n);
    const quorum = account.qual.slice(0, 3);
    const ms = await depositMultisig(
      darkPool,
      token,
      alice,
      100n,
      account.owner,
      assetFr,
      12n,
    );
    const tree = await newSeededTree();
    await tree.insert(ms.commitment);
    const nullifier = await computeNullifier(ms.psi, toFr(1n));
    const bobInKey = evenYEphemeral(556n);
    const bobInPub = publicKey(bobInKey);
    const parents = packParents([{ leafIndex: 1 }, { leafIndex: 0 }]);
    const memo = await mintIncomingNote(
      subgroupScalar(0x9911n),
      40n,
      bobInPub,
      bobInKey,
      assetFr,
      parents,
    );
    const changeEph = evenYEphemeral(2202n);
    const change = await buildMultisigNote(
      changeEph,
      60n,
      account.owner,
      assetFr,
      parents,
    );
    const m = await frost.msgTransfer({
      root: tree.getRoot().toBigInt(),
      nullifier: nullifier.toBigInt(),
      memoLeaf: memo.commitment.toBigInt(),
      changeLeaf: change.commitment.toBigInt(),
      asset: assetFr.toBigInt(),
    });
    const { R, z } = await frostSign(account.gpk, account.shares, quorum, m);
    const proof = await proveTransferMultisig({
      compliancePk: COMPLIANCE_PK,
      gpk: account.gpk,
      frostR: R,
      frostZ: toFr(z),
      recipientInPub: bobInPub,
      oldNote: ms.noteInput,
      oldNoteIndex: 1,
      oldNotePath: tree.getMerklePath(1),
      memoNote: memo.note,
      memoEph: memo.eph,
      changeNote: change.noteInput,
      changeEph,
    });
    const receipt = await (
      await darkPool
        .connect(alice)
        .transferMultisig(proof.proof, proof.publicInputs)
    ).wait();
    record("transferMultisig", receipt?.gasUsed);
  });

  it("splitMultisig", async function () {
    const { darkPool, token, alice } = await loadFixture(deployDarkPoolFixture);
    const assetFr = addressToFr(await token.getAddress());
    const account = await frostAccountDkg(5, 3, 0x484f574c03n);
    const quorum = account.qual.slice(0, 3);
    const ms = await depositMultisig(
      darkPool,
      token,
      alice,
      100n,
      account.owner,
      assetFr,
      13n,
    );
    const tree = await newSeededTree();
    await tree.insert(ms.commitment);
    const nullifier = await computeNullifier(ms.psi, toFr(1n));
    const outParents = packParents([{ leafIndex: 1 }, { leafIndex: 0 }]);
    const eph1 = evenYEphemeral(2301n);
    const eph2 = evenYEphemeral(9302n);
    const out1 = await buildMultisigNote(
      eph1,
      40n,
      account.owner,
      assetFr,
      outParents,
    );
    const out2 = await buildMultisigNote(
      eph2,
      60n,
      account.owner,
      assetFr,
      outParents,
    );
    const m = await frost.msgSplit({
      root: tree.getRoot().toBigInt(),
      nullifier: nullifier.toBigInt(),
      out1Leaf: out1.commitment.toBigInt(),
      out2Leaf: out2.commitment.toBigInt(),
      asset: assetFr.toBigInt(),
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
    const receipt = await (
      await darkPool
        .connect(alice)
        .splitMultisig(proof.proof, proof.publicInputs)
    ).wait();
    record("splitMultisig", receipt?.gasUsed);
  });

  it("joinMultisig", async function () {
    const { darkPool, token, alice } = await loadFixture(deployDarkPoolFixture);
    const assetFr = addressToFr(await token.getAddress());
    const account = await frostAccountDkg(5, 3, 0x484f574c04n);
    const quorum = account.qual.slice(0, 3);
    const msA = await depositMultisig(
      darkPool,
      token,
      alice,
      100n,
      account.owner,
      assetFr,
      14n,
    );
    const msB = await depositMultisig(
      darkPool,
      token,
      alice,
      50n,
      account.owner,
      assetFr,
      15n,
    );
    const tree = await newSeededTree();
    await tree.insert(msA.commitment);
    await tree.insert(msB.commitment);
    const nfA = await computeNullifier(msA.psi, toFr(1n));
    const nfB = await computeNullifier(msB.psi, toFr(2n));
    const outEph = evenYEphemeral(2401n);
    const out = await buildMultisigNote(
      outEph,
      150n,
      account.owner,
      assetFr,
      packParents([{ leafIndex: 1 }, { leafIndex: 2 }]),
    );
    const m = await frost.msgJoin({
      root: tree.getRoot().toBigInt(),
      nullifierA: nfA.toBigInt(),
      nullifierB: nfB.toBigInt(),
      outLeaf: out.commitment.toBigInt(),
      asset: assetFr.toBigInt(),
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
    const receipt = await (
      await darkPool
        .connect(alice)
        .joinMultisig(proof.proof, proof.publicInputs)
    ).wait();
    record("joinMultisig", receipt?.gasUsed);
  });
});
