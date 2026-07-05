import { expect } from "chai";
import { ethers } from "hardhat";
import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import { deployDarkPoolFixture, COMPLIANCE_SK } from "../helpers/fixtures";
import { TestWallet } from "../helpers/TestWallet";
import { ComplianceService } from "../helpers/ComplianceService";
import { Fr } from "@hisoka/wallets";
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
      await wAlice.syncTree(c);
      await wBob.syncTree(c);
      await wCharlie.syncTree(c);
    };

    const dep = await wAlice.deposit(ethers.parseEther("100"));
    await syncAll(dep.commitment);
    await wAlice.sync();

    const bobAddr = await wBob.getReceiveAddress();
    const tx1 = await wAlice.transfer(ethers.parseEther("50"), bobAddr.inPub);
    await syncAll(tx1.memoCommitment);
    await syncAll(tx1.changeCommitment);
    await wBob.sync();

    const charlieAddr = await wCharlie.getReceiveAddress();
    const tx2 = await wBob.transfer(ethers.parseEther("25"), charlieAddr.inPub);
    await syncAll(tx2.memoCommitment);
    await syncAll(tx2.changeCommitment);
    await wCharlie.sync();

    const aliceAddr = await wAlice.getReceiveAddress();
    await wCharlie.transfer(ethers.parseEther("10"), aliceAddr.inPub);

    const auditor = new ComplianceService(
      COMPLIANCE_SK,
      darkPool as unknown as Contract,
      0,
    );
    await auditor.sync();
    const graph = await auditor.traceTransactions();

    // TX 1: Deposit (no spent inputs, one 100 output)
    const depositTx = graph.find(
      (tx) =>
        tx.inputs.length === 0 &&
        tx.outputs[0].note.value === ethers.parseEther("100"),
    );
    expect(depositTx).to.not.equal(undefined);
    const aliceNoteCommitment = depositTx!.outputs[0].commitment;

    // TX 2: Alice -> Bob (100 -> 50 memo + 50 change)
    const txAliceToBob = graph.find((tx) =>
      tx.inputs.some((i) => i.commitment === aliceNoteCommitment),
    );
    expect(txAliceToBob).to.not.equal(undefined);
    expect(txAliceToBob!.outputs.length).to.equal(2);

    const bobMemo = txAliceToBob!.outputs.find(
      (o) => o.note.value === ethers.parseEther("50") && o.isTransfer === true,
    );
    expect(
      bobMemo,
      "Compliance failed to identify the Transfer Note to Bob",
    ).to.not.equal(undefined);

    // TX 3: Bob -> Charlie
    const txBobToCharlie = graph.find((tx) =>
      tx.inputs.some((i) => i.commitment === bobMemo!.commitment),
    );
    expect(txBobToCharlie).to.not.equal(undefined);

    const charlieMemo = txBobToCharlie!.outputs.find(
      (o) => o.note.value === ethers.parseEther("25") && o.isTransfer === true,
    );
    expect(charlieMemo).to.not.equal(undefined);

    // TX 4: Charlie -> Alice
    const txCharlieToAlice = graph.find((tx) =>
      tx.inputs.some((i) => i.commitment === charlieMemo!.commitment),
    );
    expect(txCharlieToAlice).to.not.equal(undefined);

    const aliceReceived = txCharlieToAlice!.outputs.find(
      (o) => o.note.value === ethers.parseEther("10") && o.isTransfer === true,
    );
    expect(aliceReceived).to.not.equal(undefined);
  });
});
