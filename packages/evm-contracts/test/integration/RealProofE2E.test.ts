import { expect } from "chai";
import { ethers } from "hardhat";
import { loadFixture, time } from "@nomicfoundation/hardhat-network-helpers";
import {
  deployDarkPoolFixture,
  makeDeposit,
  mintSelfNote,
  mintIncomingNote,
  mintIncomingMultisigNote,
  evenYEphemeral,
  subgroupScalar,
  userSpendScalar,
  newSeededTree,
  genesisLeaf,
  COMPLIANCE_PK,
} from "../helpers/fixtures";
import {
  toFr,
  addressToFr,
  packParents,
  PARENTS_HIDDEN,
  publicKey,
  computeNullifier,
  recoverEvenY,
  unwrapCek,
  demDecrypt,
  deriveCek,
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
import {
  buildMultisigNote,
  frostSign,
  depositMultisig,
} from "../helpers/frostMultisig";
import { statSync, readdirSync, existsSync } from "fs";
import { resolve, join } from "path";

// Freshness tripwire: proofs come from the prover's BUNDLED bytecode, so a circuit edited without a rebuild would prove STALE bytecode and pass.
type Stamp = { path: string; mtimeMs: number };

function collectSources(dir: string, acc: string[]): void {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (entry.isDirectory()) {
      if (entry.name === "target" || entry.name === "node_modules") continue;
      collectSources(join(dir, entry.name), acc);
    } else if (entry.name.endsWith(".nr") || entry.name === "Nargo.toml") {
      acc.push(join(dir, entry.name));
    }
  }
}

function newest(files: string[]): Stamp {
  let best: Stamp = { path: "", mtimeMs: 0 };
  for (const f of files) {
    const m = statSync(f).mtimeMs;
    if (m > best.mtimeMs) best = { path: f, mtimeMs: m };
  }
  return best;
}

function oldest(files: string[]): Stamp {
  let best: Stamp = { path: "", mtimeMs: Number.POSITIVE_INFINITY };
  for (const f of files) {
    const m = statSync(f).mtimeMs;
    if (m < best.mtimeMs) best = { path: f, mtimeMs: m };
  }
  return best;
}

let freshnessChecked = false;

function assertBuiltArtifactsFresh(): void {
  if (freshnessChecked) return;
  const evm = process.cwd();
  const circuitsRoot = resolve(evm, "../circuits");
  const targetDir = resolve(circuitsRoot, "target");
  const distEntry = resolve(evm, "../prover/dist/index.js");

  if (!existsSync(distEntry) || !existsSync(targetDir)) {
    throw new Error(
      `RealProofE2E freshness tripwire -- prover bundle or circuit artifacts missing (${distEntry}). ` +
        "Run `pnpm build` before the e2e; it proves the prover's bundled bytecode.",
    );
  }

  const sources: string[] = [];
  collectSources(circuitsRoot, sources);
  const newestSource = newest(sources);

  const targetJsons = readdirSync(targetDir)
    .filter((f) => f.endsWith(".json"))
    .map((f) => join(targetDir, f));
  const oldestTarget = oldest(targetJsons);
  const distMtime = statSync(distEntry).mtimeMs;

  const stale = (
    label: string,
    artifactMs: number,
    ref: Stamp,
  ): string | null =>
    artifactMs < ref.mtimeMs
      ? `${label} is stale: ${ref.path} is newer than the built artifact. Run \`pnpm build\` before the ` +
        "e2e (a stale bundle silently proves old circuits, so this net's green would be meaningless)."
      : null;

  // Only the circuit SOURCES are a sound mtime reference: artifacts are gitignored (always newer) and a committed verifier's mtime is rewritten by git checkout.
  const problem =
    stale("prover/dist", distMtime, newestSource) ??
    stale("circuits/target", oldestTarget.mtimeMs, newestSource);

  if (problem) throw new Error(`RealProofE2E freshness tripwire -- ${problem}`);
  freshnessChecked = true;
}

const toBytes32 = (v: bigint): string =>
  ethers.zeroPadValue(ethers.toBeHex(v), 32);

function mutate(publicInputs: string[], idx: number): string[] {
  const copy = [...publicInputs];
  copy[idx] = toBytes32(BigInt(publicInputs[idx]) + 1n);
  return copy;
}

/** Corrupt one proof byte. getBytesCopy, not getBytes, which aliases its input and would corrupt the caller's pristine proof. */
function corruptProof(proof: Uint8Array): string {
  const bytes = ethers.getBytesCopy(proof);
  bytes[32] ^= 0x01;
  return ethers.hexlify(bytes);
}

/** From ONE real proof, assert the verifier rejects a corrupted proof and a mutation of EVERY public input in turn, so no field is a free rider. */
async function assertEveryInputAndProofBound(
  submit: (
    proof: Uint8Array | string,
    publicInputs: string[],
  ) => Promise<unknown>,
  proof: { proof: Uint8Array; publicInputs: string[] },
): Promise<void> {
  await expect(
    submit(corruptProof(proof.proof), proof.publicInputs),
    "a one-byte-corrupted proof must be rejected",
  ).to.be.reverted;
  for (let i = 0; i < proof.publicInputs.length; i++) {
    await expect(
      submit(proof.proof, mutate(proof.publicInputs, i)),
      `public input [${i}] must be bound to the proof`,
    ).to.be.reverted;
  }
}

describe("D1 real-proof e2e (STANDARD)", function () {
  this.timeout(600_000);

  before(assertBuiltArtifactsFresh);

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
    await assertEveryInputAndProofBound(
      (p, pi) => darkPool.connect(alice).deposit(p, pi),
      proof,
    );

    const dpBefore = await token.balanceOf(await darkPool.getAddress());
    await darkPool.connect(alice).deposit(proof.proof, proof.publicInputs);
    expect(
      (await token.balanceOf(await darkPool.getAddress())) - dpBefore,
    ).to.equal(100n);

    const tree = await newSeededTree();
    await tree.insert(built.commitment);
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
      oldNote: dep.built.note,
      spendScalar: dep.spendScalar,
      oldNoteIndex: 1,
      oldNotePath: tree.getMerklePath(1),
      changeNote: change.note,
      changeEph: change.eph,
    });

    await assertEveryInputAndProofBound(
      (p, pi) => darkPool.connect(alice).withdraw(p, pi),
      proof,
    );

    const bobBefore = await token.balanceOf(bob.address);
    await darkPool.connect(alice).withdraw(proof.proof, proof.publicInputs);

    expect((await token.balanceOf(bob.address)) - bobBefore).to.equal(40n);
    expect(await darkPool.isNullifierSpent(proof.publicInputs[5])).to.equal(
      true,
    );
    await tree.insert(change.commitment);
    expect(await darkPool.getCurrentRoot()).to.equal(tree.getRoot().toString());
  });

  it("privateTransfer: inserts memo then change, spends the nullifier, verifier rejects a mutated memo leaf", async function () {
    const { darkPool, token, alice } = await loadFixture(deployDarkPoolFixture);
    const assetFr = addressToFr(await token.getAddress());
    const dep = await makeDeposit(darkPool, token, alice, 100n);
    const tree = await newSeededTree();
    await tree.insert(dep.commitment);

    const bobInKey = evenYEphemeral(555n);
    const bobInPub = publicKey(bobInKey);
    const parents = packParents([{ leafIndex: 1 }, { leafIndex: 0 }]);
    const memo = await mintIncomingNote(
      evenYEphemeral(12345n),
      40n,
      bobInPub,
      bobInKey,
      assetFr,
      PARENTS_HIDDEN,
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
      oldNote: dep.built.note,
      spendScalar: dep.spendScalar,
      oldNoteIndex: 1,
      oldNotePath: tree.getMerklePath(1),
      memoNote: memo.note,
      memoEph: memo.eph,
      changeNote: change.note,
      changeEph: change.eph,
    });

    await assertEveryInputAndProofBound(
      (p, pi) => darkPool.connect(alice).privateTransfer(p, pi),
      proof,
    );

    await darkPool
      .connect(alice)
      .privateTransfer(proof.proof, proof.publicInputs);

    expect(await darkPool.isNullifierSpent(proof.publicInputs[2])).to.equal(
      true,
    );
    await tree.insert(memo.commitment);
    await tree.insert(change.commitment);
    expect(await darkPool.getCurrentRoot()).to.equal(tree.getRoot().toString());
  });

  it("privateTransfer to a MULTISIG account: memo is owned by gpk but discoverable/readable via V", async function () {
    const { darkPool, token, alice } = await loadFixture(deployDarkPoolFixture);
    const assetFr = addressToFr(await token.getAddress());
    const dep = await makeDeposit(darkPool, token, alice, 100n);
    const tree = await newSeededTree();
    await tree.insert(dep.commitment);

    const account = await frostAccountDkg(5, 3, 0x484f574c20n);
    const v = subgroupScalar(0x1e4n);
    const parents = packParents([{ leafIndex: 1 }, { leafIndex: 0 }]);
    const memo = await mintIncomingMultisigNote(
      evenYEphemeral(24680n),
      40n,
      account.gpk,
      v,
      assetFr,
      PARENTS_HIDDEN,
    );
    const change = await mintSelfNote(
      evenYEphemeral(13579n),
      60n,
      dep.spendScalar,
      assetFr,
      parents,
    );

    const proof = await proveTransfer({
      compliancePk: COMPLIANCE_PK,
      recipientMultisig: { gpk: account.gpk, viewPub: publicKey(v) },
      oldNote: dep.built.note,
      spendScalar: dep.spendScalar,
      oldNoteIndex: 1,
      oldNotePath: tree.getMerklePath(1),
      memoNote: memo.note,
      memoEph: memo.eph,
      changeNote: change.note,
      changeEph: change.eph,
    });

    await assertEveryInputAndProofBound(
      (p, pi) => darkPool.connect(alice).privateTransfer(p, pi),
      proof,
    );
    await darkPool
      .connect(alice)
      .privateTransfer(proof.proof, proof.publicInputs);

    // The discovery tag is V.x, not gpk.x: that is what makes the note findable by members who cannot ECDH.
    expect(memo.note.owner.toBigInt()).to.equal(account.owner.toBigInt());
    expect(proof.publicInputs[6]).to.equal(toBytes32(publicKey(v)[0]));
    await tree.insert(memo.commitment);
    await tree.insert(change.commitment);
    expect(await darkPool.getCurrentRoot()).to.equal(tree.getRoot().toString());

    const recoveredEphPub = recoverEvenY(BigInt(proof.publicInputs[5]));
    const memberCek = await unwrapCek(
      toFr(BigInt(proof.publicInputs[7])),
      v,
      recoveredEphPub,
    );
    expect(memberCek.toBigInt(), "member recovers the CEK via V").to.equal(
      memo.cek.toBigInt(),
    );

    const plaintext = await demDecrypt(
      memberCek,
      proof.publicInputs.slice(8, 15).map((h: string) => toFr(BigInt(h))),
    );
    expect(plaintext[2].toBigInt(), "note_type MULTISIG").to.equal(1n);
    expect(plaintext[4].toBigInt(), "value").to.equal(40n);
    expect(plaintext[5].toBigInt(), "owner == Poseidon2(gpk)").to.equal(
      account.owner.toBigInt(),
    );

    expect(deriveCek(memo.eph, COMPLIANCE_PK).toBigInt()).to.equal(
      memo.cek.toBigInt(),
    );

    const quorum = account.qual.slice(0, 3);
    const nullifier = await computeNullifier(memo.psi, toFr(2n));
    const msChangeEph = evenYEphemeral(2468n);
    const msChange = await buildMultisigNote(
      msChangeEph,
      15n,
      account.owner,
      assetFr,
      packParents([{ leafIndex: 2 }, { leafIndex: 0 }]),
    );
    const m = await frost.msgWithdraw({
      root: tree.getRoot().toBigInt(),
      nullifier: nullifier.toBigInt(),
      changeLeaf: msChange.commitment.toBigInt(),
      publicOut: 25n,
      asset: assetFr.toBigInt(),
      recipient: addressToFr(alice.address).toBigInt(),
      intentHash: 0n,
    });
    const { R, z } = await frostSign(account.gpk, account.shares, quorum, m);
    const spendProof = await proveWithdrawMultisig({
      withdrawValue: toFr(25n),
      recipient: addressToFr(alice.address),
      intentHash: toFr(0n),
      compliancePk: COMPLIANCE_PK,
      gpk: account.gpk,
      frostR: R,
      frostZ: toFr(z),
      oldNote: memo.note,
      oldNoteIndex: 2,
      oldNotePath: tree.getMerklePath(2),
      changeNote: msChange.noteInput,
      changeEph: msChangeEph,
    });

    const before = await token.balanceOf(alice.address);
    await darkPool
      .connect(alice)
      .withdrawMultisig(spendProof.proof, spendProof.publicInputs);
    expect(
      (await token.balanceOf(alice.address)) - before,
      "the received multisig note must be spendable by its quorum",
    ).to.equal(25n);
    expect(
      await darkPool.isNullifierSpent(spendProof.publicInputs[5]),
    ).to.equal(true);
  });

  it("split: inserts out1 then out2, spends the nullifier, verifier rejects a mutated out1 leaf", async function () {
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
      noteIn: dep.built.note,
      spendScalar: dep.spendScalar,
      indexIn: 1,
      pathIn: tree.getMerklePath(1),
      noteOut1: out1.note,
      eph1: out1.eph,
      noteOut2: out2.note,
      eph2: out2.eph,
    });

    await assertEveryInputAndProofBound(
      (p, pi) => darkPool.connect(alice).split(p, pi),
      proof,
    );

    await darkPool.connect(alice).split(proof.proof, proof.publicInputs);

    expect(await darkPool.isNullifierSpent(proof.publicInputs[2])).to.equal(
      true,
    );
    await tree.insert(out1.commitment);
    await tree.insert(out2.commitment);
    expect(await darkPool.getCurrentRoot()).to.equal(tree.getRoot().toString());
  });

  it("join: merges two notes, spends both nullifiers, verifier rejects a mutated out leaf", async function () {
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
    });

    await assertEveryInputAndProofBound(
      (p, pi) => darkPool.connect(alice).join(p, pi),
      proof,
    );

    await darkPool.connect(alice).join(proof.proof, proof.publicInputs);

    expect(await darkPool.isNullifierSpent(proof.publicInputs[2])).to.equal(
      true,
    );
    expect(await darkPool.isNullifierSpent(proof.publicInputs[3])).to.equal(
      true,
    );
    await tree.insert(out.commitment);
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

    await assertEveryInputAndProofBound(
      (p, pi) => darkPool.connect(alice).publicClaim(p, pi),
      proof,
    );

    await darkPool.connect(alice).publicClaim(proof.proof, proof.publicInputs);

    expect(await darkPool.isPublicMemoSpent(memoId)).to.equal(true);
    const tree = await newSeededTree();
    await tree.insert(outNote.commitment);
    expect(await darkPool.getCurrentRoot()).to.equal(tree.getRoot().toString());
    expect(await darkPool.getNextLeafIndex()).to.equal(2n);
  });
});

describe("D1 real-proof e2e (MULTISIG, real 3-of-5 FROST account)", function () {
  this.timeout(600_000);

  before(assertBuiltArtifactsFresh);

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

    // Root [6] is a contract precheck (isKnownRoot) that runs before the verifier: a specific InvalidRoot.
    await expect(
      darkPool
        .connect(alice)
        .withdrawMultisig(proof.proof, mutate(proof.publicInputs, 6)),
    ).to.be.revertedWithCustomError(darkPool, "InvalidRoot");
    await assertEveryInputAndProofBound(
      (p, pi) => darkPool.connect(alice).withdrawMultisig(p, pi),
      proof,
    );

    const bobBefore = await token.balanceOf(bob.address);
    await darkPool
      .connect(alice)
      .withdrawMultisig(proof.proof, proof.publicInputs);

    expect((await token.balanceOf(bob.address)) - bobBefore).to.equal(40n);
    expect(await darkPool.isNullifierSpent(proof.publicInputs[5])).to.equal(
      true,
    );
    await tree.insert(change.commitment);
    expect(await darkPool.getCurrentRoot()).to.equal(tree.getRoot().toString());
  });

  // The prover throws at witness generation on mint_self_note_multisig's owner pin, so no proof of an off-gpk change owner exists.
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
    await tree.insert(ms.commitment);
    const nullifier = await computeNullifier(ms.psi, toFr(1n));

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
    await tree.insert(ms.commitment);
    const nullifier = await computeNullifier(ms.psi, toFr(1n));

    const bobInKey = evenYEphemeral(556n);
    const bobInPub = publicKey(bobInKey);
    const parents = packParents([{ leafIndex: 1 }, { leafIndex: 0 }]);
    const memo = await mintIncomingNote(
      evenYEphemeral(0x9911n),
      40n,
      bobInPub,
      bobInKey,
      assetFr,
      PARENTS_HIDDEN,
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
      memoTag: bobInPub[0],
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

    await expect(
      darkPool
        .connect(alice)
        .transferMultisig(proof.proof, mutate(proof.publicInputs, 3)),
    ).to.be.revertedWithCustomError(darkPool, "InvalidRoot");
    await assertEveryInputAndProofBound(
      (p, pi) => darkPool.connect(alice).transferMultisig(p, pi),
      proof,
    );

    await darkPool
      .connect(alice)
      .transferMultisig(proof.proof, proof.publicInputs);

    expect(await darkPool.isNullifierSpent(proof.publicInputs[2])).to.equal(
      true,
    );
    await tree.insert(memo.commitment);
    await tree.insert(change.commitment);
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

    await expect(
      darkPool
        .connect(alice)
        .splitMultisig(proof.proof, mutate(proof.publicInputs, 3)),
    ).to.be.revertedWithCustomError(darkPool, "InvalidRoot");
    await assertEveryInputAndProofBound(
      (p, pi) => darkPool.connect(alice).splitMultisig(p, pi),
      proof,
    );

    await darkPool
      .connect(alice)
      .splitMultisig(proof.proof, proof.publicInputs);

    expect(await darkPool.isNullifierSpent(proof.publicInputs[2])).to.equal(
      true,
    );
    await tree.insert(out1.commitment);
    await tree.insert(out2.commitment);
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
    await tree.insert(msA.commitment);
    await tree.insert(msB.commitment);
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

    await expect(
      darkPool
        .connect(alice)
        .joinMultisig(proof.proof, mutate(proof.publicInputs, 4)),
    ).to.be.revertedWithCustomError(darkPool, "InvalidRoot");
    await assertEveryInputAndProofBound(
      (p, pi) => darkPool.connect(alice).joinMultisig(p, pi),
      proof,
    );

    await darkPool.connect(alice).joinMultisig(proof.proof, proof.publicInputs);

    expect(await darkPool.isNullifierSpent(proof.publicInputs[2])).to.equal(
      true,
    );
    expect(await darkPool.isNullifierSpent(proof.publicInputs[3])).to.equal(
      true,
    );
    await tree.insert(out.commitment);
    expect(await darkPool.getCurrentRoot()).to.equal(tree.getRoot().toString());
  });
});
