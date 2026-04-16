import { expect } from "chai";
import { ethers } from "hardhat";
import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import { deployDarkPoolFixture, COMPLIANCE_PK } from "../helpers/fixtures";
import { TestWallet } from "../helpers/TestWallet";
import { generateDLEQProof } from "@hisoka/wallets";

describe("Integration: The Real World Simulation", function () {
  // Extended timeout for multiple proof generations and sync operations
  this.timeout(1200000);

  it("should simulate a multi-hop economy: Alice -> Bob -> Charlie -> Withdraw", async function () {
    const { darkPool, token, alice, bob, charlie } = await loadFixture(
      deployDarkPoolFixture,
    );

    const AMOUNT_DEPOSIT = ethers.parseEther("100");
    const AMOUNT_TRANSFER_1 = ethers.parseEther("50");
    const AMOUNT_TRANSFER_2 = ethers.parseEther("25");
    const INITIAL_BALANCE = ethers.parseEther("10000");

    // --- 0. BOOTSTRAP WALLETS ---
    console.log("\n[0] Bootstrapping Wallets...");
    const aliceWallet = await TestWallet.create(alice, darkPool, token);
    const bobWallet = await TestWallet.create(bob, darkPool, token);
    const charlieWallet = await TestWallet.create(charlie, darkPool, token);

    // --- STEP 1: ALICE ENTERS THE POOL ---
    console.log("[1] Alice Deposits 100 tokens...");
    const depRes = await aliceWallet.deposit(AMOUNT_DEPOSIT);

    // Network Propagation: Everyone sees the new leaf on-chain
    await bobWallet.syncTree(depRes.commitment);
    await charlieWallet.syncTree(depRes.commitment);

    // Alice Syncs: Finds her own note via ScanEngine
    console.log("    Alice Syncing...");
    await aliceWallet.sync();

    expect(aliceWallet.getBalance()).to.equal(AMOUNT_DEPOSIT);
    expect(await token.balanceOf(alice.address)).to.equal(
      INITIAL_BALANCE - AMOUNT_DEPOSIT,
    );

    // --- STEP 2: ALICE TRANSFERS TO BOB ---
    console.log("[2] Alice Transfers 50 to Bob...");

    // 1. Bob prepares his wallet to receive (Registers Tag for Index 0)
    await bobWallet.keyRepo.advanceIncomingKeys(1);

    // 2. Bob gets his ACTUAL key for Index 0
    const bobIvk = await bobWallet.account.getIncomingViewingKey(0n);
    // 3. Bob generates the address using that key
    const bobAddr = await generateDLEQProof(bobIvk.toBigInt(), COMPLIANCE_PK);

    // Alice executes transfer
    const trf1 = await aliceWallet.transfer(
      AMOUNT_TRANSFER_1,
      bobAddr.B,
      bobAddr.P,
      bobAddr.pi,
    );

    // Network Propagation: 2 New Leaves (Memo + Change)
    await bobWallet.syncTree(trf1.memoCommitment);
    await bobWallet.syncTree(trf1.changeCommitment);
    await charlieWallet.syncTree(trf1.memoCommitment);
    await charlieWallet.syncTree(trf1.changeCommitment);

    // Sync Wallets
    console.log("    Bob Syncing (Looking for Memo)...");
    await bobWallet.sync();

    console.log("    Alice Syncing (Looking for Change)...");
    await aliceWallet.sync();

    // Verification
    expect(aliceWallet.getBalance()).to.equal(
      AMOUNT_DEPOSIT - AMOUNT_TRANSFER_1,
    ); // 50
    expect(bobWallet.getBalance()).to.equal(AMOUNT_TRANSFER_1); // 50

    // Verify Path B flag (Bob received this note)
    const bobNotes = bobWallet.utxoRepo.getUnspentNotes();
    expect(bobNotes[0].isTransfer).to.equal(true);

    // --- STEP 3: BOB TRANSFERS TO CHARLIE ---
    console.log("[3] Bob Transfers 25 to Charlie...");

    // Charlie prepares
    await charlieWallet.keyRepo.advanceIncomingKeys(1);
    const charlieIvk = await charlieWallet.account.getIncomingViewingKey(0n);
    const charlieAddr = await generateDLEQProof(
      charlieIvk.toBigInt(),
      COMPLIANCE_PK,
    );

    // Bob spends his received note
    const trf2 = await bobWallet.transfer(
      AMOUNT_TRANSFER_2,
      charlieAddr.B,
      charlieAddr.P,
      charlieAddr.pi,
    );

    // Network Propagation
    await aliceWallet.syncTree(trf2.memoCommitment);
    await aliceWallet.syncTree(trf2.changeCommitment);
    await charlieWallet.syncTree(trf2.memoCommitment);
    await charlieWallet.syncTree(trf2.changeCommitment);

    // Sync Wallets
    console.log("    Charlie Syncing...");
    await charlieWallet.sync();
    console.log("    Bob Syncing...");
    await bobWallet.sync();

    expect(charlieWallet.getBalance()).to.equal(AMOUNT_TRANSFER_2); // 25
    expect(bobWallet.getBalance()).to.equal(
      AMOUNT_TRANSFER_1 - AMOUNT_TRANSFER_2,
    ); // 25

    // --- STEP 4: CHARLIE WITHDRAWS ---
    console.log("[4] Charlie Withdraws 25...");

    await charlieWallet.withdraw(AMOUNT_TRANSFER_2);

    console.log("    Charlie Syncing (Marking Spent)...");
    await charlieWallet.sync();

    expect(charlieWallet.getBalance()).to.equal(0n);

    const expectedBal = INITIAL_BALANCE + AMOUNT_TRANSFER_2;
    expect(await token.balanceOf(charlie.address)).to.equal(expectedBal);

    console.log("\n[OK] REAL WORLD SCENARIO COMPLETE");
  });
});
