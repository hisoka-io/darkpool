import { expect } from "chai";
import { ethers } from "hardhat";
import { time, loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import {
  deployDarkPoolFixture,
  makeDeposit,
  COMPLIANCE_PK,
} from "../helpers/fixtures";
import {
  toFr,
  addressToFr,
  LeanIMT,
  deriveSharedSecret,
  NotePlaintext,
  Poseidon,
} from "@hisoka/wallets";
import { proveWithdraw, WithdrawInputs } from "@hisoka/prover";

describe("Integration: Programmability (Timelocks & Hashlocks)", function () {
  it("should enforce Timelocks on withdrawals", async function () {
    const { darkPool, token, alice } = await loadFixture(deployDarkPoolFixture);

    // 1. Setup: Deposit 100
    const { depositPlain, ephemeralSk, commitment } = await makeDeposit(
      darkPool,
      token,
      alice,
      100n,
    );
    const tree = new LeanIMT(32);
    await tree.insert(commitment);

    // 2. Create a Time-Locked Note via Self-Transfer (Withdraw 0)
    const unlockTime = (await time.latest()) + 3600;
    const assetFr = addressToFr(await token.getAddress());

    const lockedNote: NotePlaintext = {
      value: toFr(100n),
      asset_id: assetFr,
      secret: toFr(123n),
      nullifier: toFr(456n),
      timelock: toFr(unlockTime), // SET TIMELOCK
      hashlock: toFr(0n),
    };

    // Input to create the lock
    const lockInputs: WithdrawInputs = {
      withdrawValue: toFr(0n),
      recipient: addressToFr(alice.address),
      merkleRoot: tree.getRoot(),
      currentTimestamp: await time.latest(),
      intentHash: toFr(0),
      compliancePk: COMPLIANCE_PK,
      oldNote: depositPlain,
      oldSharedSecret: await deriveSharedSecret(ephemeralSk, COMPLIANCE_PK),
      oldNoteIndex: 0,
      oldNotePath: Array(32).fill(toFr(0n)),
      hashlockPreimage: toFr(0n),
      changeNote: lockedNote,
      changeEphemeralSk: toFr(999n),
    };

    const lockProof = await proveWithdraw(lockInputs);
    await darkPool
      .connect(alice)
      .withdraw(lockProof.proof, lockProof.publicInputs);

    // Update Tree with the locked note (Index 1)
    // Withdraw 18 Inputs -> [10..16] is change_ct
    const lockedPub = lockProof.publicInputs.map((s) => toFr(s));
    const lockedCt = lockedPub.slice(10, 17);
    const lockedCommitment = await Poseidon.hash(lockedCt);
    await tree.insert(lockedCommitment);

    // 3. Attempt to Spend Locked Note IMMEDIATELY (Should Fail)
    const lockedEphSk = toFr(999n);
    const lockedSharedSecret = await deriveSharedSecret(
      lockedEphSk,
      COMPLIANCE_PK,
    );

    const spendPath = Array(32).fill(toFr(0n));
    spendPath[0] = commitment; // Sibling is Index 0

    const spendInputs: WithdrawInputs = {
      withdrawValue: toFr(100n),
      recipient: addressToFr(alice.address),
      merkleRoot: tree.getRoot(),
      currentTimestamp: await time.latest(), // Time is < unlockTime
      intentHash: toFr(0),
      compliancePk: COMPLIANCE_PK,
      oldNote: lockedNote,
      oldSharedSecret: lockedSharedSecret,
      oldNoteIndex: 1,
      oldNotePath: spendPath,
      hashlockPreimage: toFr(0n),
      changeNote: { ...lockedNote, value: toFr(0n) },
      changeEphemeralSk: toFr(888n),
    };

    // Explicit check for failure
    let failed = false;
    try {
      await proveWithdraw(spendInputs);
    } catch {
      failed = true;
    }
    expect(failed, "Proof generation should fail (Timelock not met)").to.equal(
      true,
    );

    // 4. Advance Time
    await time.increaseTo(unlockTime + 10); // Buffer to be safe

    // 5. Attempt Spend AGAIN (Should Pass)
    spendInputs.currentTimestamp = await time.latest();

    const validProof = await proveWithdraw(spendInputs);
    await darkPool
      .connect(alice)
      .withdraw(validProof.proof, validProof.publicInputs);

    // Balance check: 10000 start - 100 dep + 0 wdw + 100 wdw = 10000
    expect(await token.balanceOf(alice.address)).to.equal(
      ethers.parseEther("10000"),
    );
  });

  it("should enforce Hashlocks on withdrawals", async function () {
    const { darkPool, token, alice } = await loadFixture(deployDarkPoolFixture);

    // 1. Setup: Deposit 100
    const { depositPlain, ephemeralSk, commitment } = await makeDeposit(
      darkPool,
      token,
      alice,
      100n,
    );
    const tree = new LeanIMT(32);
    await tree.insert(commitment);

    // 2. Create Hashlocked Note
    const secretPreimage = 1337n;
    const hashlock = await Poseidon.hashScalar(toFr(secretPreimage));

    const lockedNote: NotePlaintext = {
      value: toFr(100n),
      asset_id: depositPlain.asset_id,
      secret: toFr(1n),
      nullifier: toFr(2n),
      timelock: toFr(0n),
      hashlock: hashlock, // SET HASHLOCK
    };

    const lockInputs: WithdrawInputs = {
      withdrawValue: toFr(0n),
      recipient: addressToFr(alice.address),
      merkleRoot: tree.getRoot(),
      currentTimestamp: await time.latest(),
      intentHash: toFr(0),
      compliancePk: COMPLIANCE_PK,
      oldNote: depositPlain,
      oldSharedSecret: await deriveSharedSecret(ephemeralSk, COMPLIANCE_PK),
      oldNoteIndex: 0,
      oldNotePath: Array(32).fill(toFr(0n)),
      hashlockPreimage: toFr(0n),
      changeNote: lockedNote,
      changeEphemeralSk: toFr(999n),
    };
    const lockProof = await proveWithdraw(lockInputs);
    await darkPool
      .connect(alice)
      .withdraw(lockProof.proof, lockProof.publicInputs);

    // Update Tree (Index 1)
    const lockedPub = lockProof.publicInputs.map((s) => toFr(s));
    const lockedCommitment = await Poseidon.hash(lockedPub.slice(10, 17));
    await tree.insert(lockedCommitment);

    const lockedSharedSecret = await deriveSharedSecret(
      toFr(999n),
      COMPLIANCE_PK,
    );
    const spendPath = Array(32).fill(toFr(0n));
    spendPath[0] = commitment;

    // 3. Attempt Spend with WRONG Preimage
    const badInputs: WithdrawInputs = {
      withdrawValue: toFr(100n),
      recipient: addressToFr(alice.address),
      merkleRoot: tree.getRoot(),
      currentTimestamp: await time.latest(),
      intentHash: toFr(0),
      compliancePk: COMPLIANCE_PK,
      oldNote: lockedNote,
      oldSharedSecret: lockedSharedSecret,
      oldNoteIndex: 1,
      oldNotePath: spendPath,
      hashlockPreimage: toFr(999999n), // WRONG PREIMAGE
      changeNote: { ...lockedNote, value: toFr(0n) },
      changeEphemeralSk: toFr(888n),
    };

    // Explicit check
    let failed = false;
    try {
      await proveWithdraw(badInputs);
    } catch {
      failed = true;
    }
    expect(failed, "Proof generation should fail (Wrong Preimage)").to.equal(
      true,
    );

    // 4. Attempt Spend with CORRECT Preimage
    const goodInputs = { ...badInputs, hashlockPreimage: toFr(secretPreimage) };
    const validProof = await proveWithdraw(goodInputs);

    await darkPool
      .connect(alice)
      .withdraw(validProof.proof, validProof.publicInputs);
    expect(await token.balanceOf(alice.address)).to.equal(
      ethers.parseEther("10000"),
    );
  });
});
