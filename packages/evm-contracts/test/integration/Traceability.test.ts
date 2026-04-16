import { expect } from "chai";
import { ethers } from "hardhat";
import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import {
  deployDarkPoolFixture,
  COMPLIANCE_SK,
  COMPLIANCE_PK,
} from "../helpers/fixtures";
import { TestWallet } from "../helpers/TestWallet";
import { ComplianceService } from "../helpers/ComplianceService";
import { Fr, generateDLEQProof, toFr } from "@hisoka/wallets";
import { Contract } from "ethers";

describe("Compliance: Traceability & Auditing", function () {
  this.timeout(1200000);

  it("should reconstruct a circular flow: Alice -> Bob -> Charlie -> Alice", async function () {
    const { darkPool, token, alice, bob, charlie } = await loadFixture(
      deployDarkPoolFixture,
    );

    const wAlice = await TestWallet.create(alice, darkPool, token);
    const wBob = await TestWallet.create(bob, darkPool, token);
    const wCharlie = await TestWallet.create(charlie, darkPool, token);

    const syncAll = async (c: Fr) => {
      const fr = c;
      await wAlice.syncTree(fr);
      await wBob.syncTree(fr);
      await wCharlie.syncTree(fr);
    };

    // --- 1. Alice Deposits 100 ---
    const dep = await wAlice.deposit(ethers.parseEther("100"));
    await syncAll(dep.commitment);
    await wAlice.sync();

    // --- 2. Alice -> Bob (50) ---
    await wBob.keyRepo.advanceIncomingKeys(1);
    const bobIvk = await wBob.account.getIncomingViewingKey(0n);
    const bobAddr = await generateDLEQProof(bobIvk.toBigInt(), COMPLIANCE_PK);

    const tx1 = await wAlice.transfer(
      ethers.parseEther("50"),
      bobAddr.B,
      bobAddr.P,
      bobAddr.pi,
    );
    await syncAll(tx1.memoCommitment);
    await syncAll(tx1.changeCommitment);
    await wBob.sync();

    // --- 3. Bob -> Charlie (25) ---
    await wCharlie.keyRepo.advanceIncomingKeys(1);
    const charlieIvk = await wCharlie.account.getIncomingViewingKey(0n);
    const charlieAddr = await generateDLEQProof(
      charlieIvk.toBigInt(),
      COMPLIANCE_PK,
    );

    const tx2 = await wBob.transfer(
      ethers.parseEther("25"),
      charlieAddr.B,
      charlieAddr.P,
      charlieAddr.pi,
    );
    await syncAll(tx2.memoCommitment);
    await syncAll(tx2.changeCommitment);
    await wCharlie.sync();

    // --- 4. Charlie -> Alice (10) ---
    await wAlice.keyRepo.advanceIncomingKeys(1);
    const aliceIvk = await wAlice.account.getIncomingViewingKey(0n);
    const aliceAddr = await generateDLEQProof(
      aliceIvk.toBigInt(),
      COMPLIANCE_PK,
    );

    await wCharlie.transfer(
      ethers.parseEther("10"),
      aliceAddr.B,
      aliceAddr.P,
      aliceAddr.pi,
    );

    // =====================================================
    // [Info] COMPLIANCE INVESTIGATION
    // =====================================================
    console.log("\n[Compliance] Starting Forensic Scan...");
    const auditor = new ComplianceService(
      COMPLIANCE_SK,
      darkPool as unknown as Contract,
    );
    await auditor.sync();
    const graph = await auditor.traceTransactions();
    console.log(`[Compliance] Reconstructed ${graph.length} Transactions.`);

    // --- ASSERTION LOGIC ---

    // TX 1: Deposit
    const depositTx = graph.find(
      (tx) =>
        tx.inputs.length === 0 &&
        tx.outputs[0].note.value.equals(toFr(ethers.parseEther("100"))),
    );
    expect(depositTx).to.not.equal(undefined);
    const aliceNoteCommitment = depositTx!.outputs[0].commitment;

    // TX 2: Alice -> Bob (100 -> 50 + 50)
    const txAliceToBob = graph.find((tx) =>
      tx.inputs.some((i) => i.commitment === aliceNoteCommitment),
    );
    expect(txAliceToBob).to.not.equal(undefined);
    expect(txAliceToBob!.outputs.length).to.equal(2);

    const bobMemo = txAliceToBob!.outputs.find(
      (o) =>
        o.note.value.equals(toFr(ethers.parseEther("50"))) &&
        o.isTransfer === true,
    );
    expect(bobMemo, "Compliance failed to identify the Transfer Note to Bob").to.not.equal(undefined);

    // TX 3: Bob -> Charlie
    const txBobToCharlie = graph.find((tx) =>
      tx.inputs.some((i) => i.commitment === bobMemo!.commitment),
    );
    expect(txBobToCharlie).to.not.equal(undefined);

    const charlieMemo = txBobToCharlie!.outputs.find(
      (o) =>
        o.note.value.equals(toFr(ethers.parseEther("25"))) &&
        o.isTransfer === true,
    );
    expect(charlieMemo).to.not.equal(undefined);

    // TX 4: Charlie -> Alice
    const txCharlieToAlice = graph.find((tx) =>
      tx.inputs.some((i) => i.commitment === charlieMemo!.commitment),
    );
    expect(txCharlieToAlice).to.not.equal(undefined);

    const aliceReceived = txCharlieToAlice!.outputs.find(
      (o) =>
        o.note.value.equals(toFr(ethers.parseEther("10"))) &&
        o.isTransfer === true,
    );
    expect(aliceReceived).to.not.equal(undefined);

    console.log(
      "[OK] Traceability Verified: Deposit -> Alice -> Bob -> Charlie -> Alice",
    );
  });
});
