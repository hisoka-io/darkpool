import { expect } from "chai";
import { ethers } from "hardhat";
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
  genesisLeaf,
  noteToInput,
  COMPLIANCE_PK,
} from "../helpers/fixtures";
import {
  Fr,
  toFr,
  addressToFr,
  packParents,
  publicKey,
  deriveCek,
  computePsi,
  computeNullifier,
  leaf,
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
  NoteInput,
} from "@hisoka/prover";
import { Base8, mulPointEscalar, Point } from "@zk-kit/baby-jubjub";

const toBytes32 = (v: bigint): string =>
  ethers.zeroPadValue(ethers.toBeHex(v), 32);

/** Flip one public input to a distinct value so the real verifier must reject the mutated proof. */
function mutate(publicInputs: string[], idx: number): string[] {
  const copy = [...publicInputs];
  copy[idx] = toBytes32(BigInt(publicInputs[idx]) + 1n);
  return copy;
}

/** A MULTISIG note (note_type == 1) owned by a FROST account (owner == Poseidon2(gpk)), ECDH-encrypted to
 *  the compliance key. Returns both the leaf commitment and the prover NoteInput view. */
async function buildMultisigNote(
  eph: Fr,
  value: bigint,
  owner: Fr,
  assetFr: Fr,
  parents: Fr,
): Promise<{ commitment: Fr; noteInput: NoteInput; psi: Fr }> {
  const cek = deriveCek(eph, COMPLIANCE_PK);
  const psi = await computePsi(cek);
  const commitment = await leaf({
    noteVersion: toFr(1n),
    assetId: assetFr,
    noteType: toFr(1n),
    conditionsHash: toFr(0n),
    value,
    owner,
    psi,
    parents,
  });
  const noteInput: NoteInput = {
    noteVersion: toFr(1n),
    assetId: assetFr,
    noteType: toFr(1n),
    conditionsHash: toFr(0n),
    value: toFr(value),
    owner,
    psi,
    parents,
  };
  return { commitment, noteInput, psi };
}

/** Run a full FROST 2-round session: `signerIds` (a t-of-n quorum) jointly sign `m` under `gpk`. */
async function frostSign(
  gpk: Point,
  shares: Map<bigint, bigint>,
  signerIds: bigint[],
  m: bigint,
): Promise<{ R: Point; z: bigint }> {
  const cs = frost.bjjCiphersuite;
  const msg = frost.encodeMessage(m);

  type Round1 = Awaited<ReturnType<typeof frost.commit<Point>>>;
  const nonceById = new Map<bigint, Round1["nonces"]>();
  const commitments: Round1["commitment"][] = [];
  for (const id of signerIds) {
    const secret = shares.get(id);
    if (secret === undefined) throw new Error(`missing share for signer ${id}`);
    const { nonces, commitment } = await frost.commit(
      cs,
      id,
      secret,
      crypto.getRandomValues(new Uint8Array(32)),
      crypto.getRandomValues(new Uint8Array(32)),
    );
    nonceById.set(id, nonces);
    commitments.push(commitment);
  }

  const rhos = await frost.bindingFactors(cs, gpk, msg, commitments);
  const R = frost.groupCommitment(cs, commitments, rhos);

  const zShares: bigint[] = [];
  for (const id of signerIds) {
    const nonces = nonceById.get(id)!;
    const secret = shares.get(id)!;
    zShares.push(
      await frost.signShare(cs, id, nonces, secret, gpk, msg, commitments),
    );
  }

  const sig = frost.aggregate(cs, R, zShares);
  expect(await frost.verify(cs, gpk, msg, sig)).to.equal(true);
  return { R: sig.R, z: sig.z };
}

// Each op proves a REAL circuit, registers the ACTUAL generated verifier (deployed in the fixture), submits
// on-chain, and asserts the real effects. The output-leaf ordering is cross-checked by rebuilding the LeanIMT
// (genesis at index 0, real notes from index 1) and asserting its root equals the contract's -- a drain-
// critical check that the contract inserts each leaf at the public-input index the layout table pins. One
// negative per op mutates a single public input and asserts the deployed verifier rejects it.
describe("D1 real-proof e2e (STANDARD)", function () {
  this.timeout(600_000);

  it("genesis parity: TS genesis leaf equals the contract initial root", async function () {
    const { darkPool } = await loadFixture(deployDarkPoolFixture);
    expect((await genesisLeaf()).toBigInt()).to.equal(
      BigInt(await darkPool.getCurrentRoot()),
    );
    expect(await darkPool.getNextLeafIndex()).to.equal(1n);
  });

  it("deposit: mints a note at index 1, pulls the exact ERC20, verifier rejects a mutated value", async function () {
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
    // Negative: mutate value [5] -> the deployed verifier rejects.
    await expect(
      darkPool
        .connect(alice)
        .deposit(proof.proof, mutate(proof.publicInputs, 5)),
    ).to.be.reverted;

    const dpBefore = await token.balanceOf(await darkPool.getAddress());
    await darkPool.connect(alice).deposit(proof.proof, proof.publicInputs);
    expect(
      (await token.balanceOf(await darkPool.getAddress())) - dpBefore,
    ).to.equal(100n);

    const tree = await newSeededTree();
    await tree.insert(built.commitment); // index 1
    expect(await darkPool.getCurrentRoot()).to.equal(tree.getRoot().toString());
    expect(await darkPool.getNextLeafIndex()).to.equal(2n);
  });

  it("withdraw: spends the note, pays the exact ERC20 to the recipient, verifier rejects a mutated recipient", async function () {
    const { darkPool, token, alice, bob } = await loadFixture(
      deployDarkPoolFixture,
    );
    const assetFr = addressToFr(await token.getAddress());
    const dep = await makeDeposit(darkPool, token, alice, 100n);
    const tree = await newSeededTree();
    await tree.insert(dep.commitment); // index 1

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

    // Negative: mutate recipient [1] -> verifier rejects (funds cannot be redirected).
    await expect(
      darkPool
        .connect(alice)
        .withdraw(proof.proof, mutate(proof.publicInputs, 1)),
    ).to.be.reverted;

    const bobBefore = await token.balanceOf(bob.address);
    await darkPool.connect(alice).withdraw(proof.proof, proof.publicInputs);

    expect((await token.balanceOf(bob.address)) - bobBefore).to.equal(40n);
    expect(await darkPool.isNullifierSpent(proof.publicInputs[5])).to.equal(
      true,
    );
    await tree.insert(change.commitment); // index 2
    expect(await darkPool.getCurrentRoot()).to.equal(tree.getRoot().toString());
  });

  it("privateTransfer: inserts memo then change, spends the nullifier, verifier rejects a mutated memo leaf", async function () {
    const { darkPool, token, alice } = await loadFixture(deployDarkPoolFixture);
    const assetFr = addressToFr(await token.getAddress());
    const dep = await makeDeposit(darkPool, token, alice, 100n);
    const tree = await newSeededTree();
    await tree.insert(dep.commitment); // index 1

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

    // Negative: mutate memo leaf [4] -> verifier rejects.
    await expect(
      darkPool
        .connect(alice)
        .privateTransfer(proof.proof, mutate(proof.publicInputs, 4)),
    ).to.be.reverted;

    await darkPool
      .connect(alice)
      .privateTransfer(proof.proof, proof.publicInputs);

    expect(await darkPool.isNullifierSpent(proof.publicInputs[2])).to.equal(
      true,
    );
    await tree.insert(memo.commitment); // index 2
    await tree.insert(change.commitment); // index 3
    expect(await darkPool.getCurrentRoot()).to.equal(tree.getRoot().toString());
  });

  it("split: inserts out1 then out2, spends the nullifier, verifier rejects a mutated out1 leaf", async function () {
    const { darkPool, token, alice } = await loadFixture(deployDarkPoolFixture);
    const assetFr = addressToFr(await token.getAddress());
    const dep = await makeDeposit(darkPool, token, alice, 100n);
    const tree = await newSeededTree();
    await tree.insert(dep.commitment); // index 1

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

    // Negative: mutate out1 leaf [4] -> verifier rejects.
    await expect(
      darkPool.connect(alice).split(proof.proof, mutate(proof.publicInputs, 4)),
    ).to.be.reverted;

    await darkPool.connect(alice).split(proof.proof, proof.publicInputs);

    expect(await darkPool.isNullifierSpent(proof.publicInputs[2])).to.equal(
      true,
    );
    await tree.insert(out1.commitment); // index 2
    await tree.insert(out2.commitment); // index 3
    expect(await darkPool.getCurrentRoot()).to.equal(tree.getRoot().toString());
  });

  it("join: merges two notes, spends both nullifiers, verifier rejects a mutated out leaf", async function () {
    const { darkPool, token, alice } = await loadFixture(deployDarkPoolFixture);
    const assetFr = addressToFr(await token.getAddress());
    const depA = await makeDeposit(darkPool, token, alice, 100n);
    const depB = await makeDeposit(darkPool, token, alice, 50n);
    const tree = await newSeededTree();
    await tree.insert(depA.commitment); // index 1
    await tree.insert(depB.commitment); // index 2

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

    // Negative: mutate out leaf [5] -> verifier rejects.
    await expect(
      darkPool.connect(alice).join(proof.proof, mutate(proof.publicInputs, 5)),
    ).to.be.reverted;

    await darkPool.connect(alice).join(proof.proof, proof.publicInputs);

    expect(await darkPool.isNullifierSpent(proof.publicInputs[2])).to.equal(
      true,
    );
    expect(await darkPool.isNullifierSpent(proof.publicInputs[3])).to.equal(
      true,
    );
    await tree.insert(out.commitment); // index 3
    expect(await darkPool.getCurrentRoot()).to.equal(tree.getRoot().toString());
  });

  it("publicClaim: consumes the memo and mints the note at index 1, verifier rejects a mutated out leaf", async function () {
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

    // Negative: mutate out leaf [4] -> verifier rejects.
    await expect(
      darkPool
        .connect(alice)
        .publicClaim(proof.proof, mutate(proof.publicInputs, 4)),
    ).to.be.reverted;

    await darkPool.connect(alice).publicClaim(proof.proof, proof.publicInputs);

    expect(await darkPool.isPublicMemoSpent(memoId)).to.equal(true);
    const tree = await newSeededTree();
    await tree.insert(outNote.commitment); // index 1
    expect(await darkPool.getCurrentRoot()).to.equal(tree.getRoot().toString());
    expect(await darkPool.getNextLeafIndex()).to.equal(2n);
  });
});

describe("D1 real-proof e2e (MULTISIG, real 3-of-5 FROST account)", function () {
  this.timeout(600_000);

  it("withdrawMultisig: a quorum authorizes the spend, pays the exact ERC20, verifier rejects a mutated recipient", async function () {
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
    await tree.insert(ms.commitment); // index 1
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

    // Root [6] is a contract precheck (isKnownRoot) that runs before the verifier: a specific InvalidRoot.
    await expect(
      darkPool
        .connect(alice)
        .withdrawMultisig(proof.proof, mutate(proof.publicInputs, 6)),
    ).to.be.revertedWithCustomError(darkPool, "InvalidRoot");
    // Recipient [1] is bound only by the proof. The deployed Honk verifier reverts INTERNALLY on a bad public
    // input (it does not return false), so the contract's InvalidProof wrapper is never reached -- assert a
    // generic revert (funds cannot be redirected).
    await expect(
      darkPool
        .connect(alice)
        .withdrawMultisig(proof.proof, mutate(proof.publicInputs, 1)),
    ).to.be.reverted;

    const bobBefore = await token.balanceOf(bob.address);
    await darkPool
      .connect(alice)
      .withdrawMultisig(proof.proof, proof.publicInputs);

    expect((await token.balanceOf(bob.address)) - bobBefore).to.equal(40n);
    expect(await darkPool.isNullifierSpent(proof.publicInputs[5])).to.equal(
      true,
    );
    await tree.insert(change.commitment); // index 2
    expect(await darkPool.getCurrentRoot()).to.equal(tree.getRoot().toString());
  });

  // H1 at the proof layer: a multisig spend cannot mint its change to an owner off the account gpk. Every
  // field is valid (including a real quorum signature) except the change owner, so the prover throws at
  // witness generation on mint_self_note_multisig's owner pin -- no proof of the theft can be produced.
  it("withdrawMultisig prover rejects an off-gpk change owner", async function () {
    const { token, bob } = await loadFixture(deployDarkPoolFixture);
    const assetFr = addressToFr(await token.getAddress());
    const account = await frostAccountDkg(5, 3, 0x484f574c0an);
    const quorum = account.qual.slice(0, 3);

    const ms = await buildMultisigNote(
      evenYEphemeral(3101n),
      100n,
      account.owner,
      assetFr,
      toFr(0n),
    );
    const tree = await newSeededTree();
    await tree.insert(ms.commitment); // index 1
    const nullifier = await computeNullifier(ms.psi, toFr(1n));

    // The change is owned OFF the account gpk (owner != Poseidon2(gpk)).
    const offGpkOwner = toFr(account.owner.toBigInt() + 1n);
    const changeEph = evenYEphemeral(3102n);
    const change = await buildMultisigNote(
      changeEph,
      60n,
      offGpkOwner,
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

    let thrown: Error | undefined;
    try {
      await proveWithdrawMultisig({
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
    } catch (err) {
      thrown = err as Error;
    }
    expect(thrown, "prover must reject an off-gpk change owner").to.not.equal(
      undefined,
    );
    expect(thrown!.message).to.match(/owned by the account gpk/);
  });

  it("transferMultisig: a quorum authorizes memo + change, verifier rejects a mutated memo leaf", async function () {
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
    await tree.insert(ms.commitment); // index 1
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

    // Root [3] is a contract precheck (isKnownRoot) that runs before the verifier: a specific InvalidRoot.
    await expect(
      darkPool
        .connect(alice)
        .transferMultisig(proof.proof, mutate(proof.publicInputs, 3)),
    ).to.be.revertedWithCustomError(darkPool, "InvalidRoot");
    // Memo leaf [4] is bound only by the proof: the deployed Honk verifier reverts INTERNALLY on a bad public
    // input, so the contract's InvalidProof wrapper is never reached -- assert a generic revert.
    await expect(
      darkPool
        .connect(alice)
        .transferMultisig(proof.proof, mutate(proof.publicInputs, 4)),
    ).to.be.reverted;

    await darkPool
      .connect(alice)
      .transferMultisig(proof.proof, proof.publicInputs);

    expect(await darkPool.isNullifierSpent(proof.publicInputs[2])).to.equal(
      true,
    );
    await tree.insert(memo.commitment); // index 2
    await tree.insert(change.commitment); // index 3
    expect(await darkPool.getCurrentRoot()).to.equal(tree.getRoot().toString());
  });

  it("splitMultisig: a quorum authorizes out1 + out2 back to the account, verifier rejects a mutated out1 leaf", async function () {
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
    await tree.insert(ms.commitment); // index 1
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

    // Root [3] is a contract precheck (isKnownRoot) that runs before the verifier: a specific InvalidRoot.
    await expect(
      darkPool
        .connect(alice)
        .splitMultisig(proof.proof, mutate(proof.publicInputs, 3)),
    ).to.be.revertedWithCustomError(darkPool, "InvalidRoot");
    // out1 leaf [4] is bound only by the proof: the deployed Honk verifier reverts INTERNALLY on a bad public
    // input, so the contract's InvalidProof wrapper is never reached -- assert a generic revert.
    await expect(
      darkPool
        .connect(alice)
        .splitMultisig(proof.proof, mutate(proof.publicInputs, 4)),
    ).to.be.reverted;

    await darkPool
      .connect(alice)
      .splitMultisig(proof.proof, proof.publicInputs);

    expect(await darkPool.isNullifierSpent(proof.publicInputs[2])).to.equal(
      true,
    );
    await tree.insert(out1.commitment); // index 2
    await tree.insert(out2.commitment); // index 3
    expect(await darkPool.getCurrentRoot()).to.equal(tree.getRoot().toString());
  });

  it("joinMultisig: two quorum signatures merge two account notes, verifier rejects a mutated out leaf", async function () {
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
    await tree.insert(msA.commitment); // index 1
    await tree.insert(msB.commitment); // index 2
    const nfA = await computeNullifier(msA.psi, toFr(1n));
    const nfB = await computeNullifier(msB.psi, toFr(2n));

    const out = await buildMultisigNote(
      evenYEphemeral(2401n),
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
      ephOut: evenYEphemeral(2401n),
    });

    // Root [4] is a contract precheck (isKnownRoot) that runs before the verifier: a specific InvalidRoot.
    await expect(
      darkPool
        .connect(alice)
        .joinMultisig(proof.proof, mutate(proof.publicInputs, 4)),
    ).to.be.revertedWithCustomError(darkPool, "InvalidRoot");
    // out leaf [5] is bound only by the proof: the deployed Honk verifier reverts INTERNALLY on a bad public
    // input, so the contract's InvalidProof wrapper is never reached -- assert a generic revert.
    await expect(
      darkPool
        .connect(alice)
        .joinMultisig(proof.proof, mutate(proof.publicInputs, 5)),
    ).to.be.reverted;

    await darkPool.connect(alice).joinMultisig(proof.proof, proof.publicInputs);

    expect(await darkPool.isNullifierSpent(proof.publicInputs[2])).to.equal(
      true,
    );
    expect(await darkPool.isNullifierSpent(proof.publicInputs[3])).to.equal(
      true,
    );
    await tree.insert(out.commitment); // index 3
    expect(await darkPool.getCurrentRoot()).to.equal(tree.getRoot().toString());
  });
});

/** Deposit a MULTISIG note (owner == Poseidon2(gpk)) for `user` so the account holds a spendable note. */
async function depositMultisig(
  darkPool: Awaited<ReturnType<typeof deployDarkPoolFixture>>["darkPool"],
  token: Awaited<ReturnType<typeof deployDarkPoolFixture>>["token"],
  user: Awaited<ReturnType<typeof deployDarkPoolFixture>>["alice"],
  value: bigint,
  owner: Fr,
  assetFr: Fr,
  ephSeed: bigint,
): Promise<{ commitment: Fr; noteInput: NoteInput; psi: Fr }> {
  const eph = evenYEphemeral(ephSeed);
  const ms = await buildMultisigNote(eph, value, owner, assetFr, toFr(0n));
  const proof = await proveDeposit({
    compliancePk: COMPLIANCE_PK,
    note: ms.noteInput,
    eph,
  });
  await token.connect(user).approve(await darkPool.getAddress(), value);
  await darkPool.connect(user).deposit(proof.proof, proof.publicInputs);
  return ms;
}
