import { expect } from "chai";
import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import {
  deployDarkPoolFixture,
  makeDeposit,
  COMPLIANCE_PK,
} from "../helpers/fixtures";
import {
  toFr,
  LeanIMT,
  deriveSharedSecret,
  NotePlaintext,
  generateDLEQProof,
} from "@hisoka/wallets";
import { proveTransfer, TransferInputs } from "@hisoka/prover";
describe("DarkPool Behavior: Private Transfer", function () {
  it("should execute a valid transfer from Alice to Bob", async function () {
    const { darkPool, token, alice } = await loadFixture(deployDarkPoolFixture);

    // 1. Setup: Alice deposits 100
    const { depositPlain, ephemeralSk, commitment } = await makeDeposit(
      darkPool,
      token,
      alice,
      100n,
    );

    // 2. Bob generates his "Hisoka Address" (DLEQ Params)
    const bob_sk = 555n; // Bob's private key
    const bob_dleq = await generateDLEQProof(bob_sk, COMPLIANCE_PK);

    // 3. Reconstruct Tree (Mocking Alice's wallet sync)
    const tree = new LeanIMT(32);
    await tree.insert(commitment);

    // 4. Prepare Transfer
    const transferValue = 40n;
    const changeValue = 60n;

    const memoPlain: NotePlaintext = {
      asset_id: depositPlain.asset_id,
      value: toFr(transferValue),
      secret: toFr(0n), // Standard Memo dummy
      nullifier: toFr(0n), // Standard Memo dummy
      timelock: toFr(0n),
      hashlock: toFr(0n),
    };

    const changePlain: NotePlaintext = {
      asset_id: depositPlain.asset_id,
      value: toFr(changeValue),
      secret: toFr(999n),
      nullifier: toFr(888n),
      timelock: toFr(0n),
      hashlock: toFr(0n),
    };

    const inputs: TransferInputs = {
      merkleRoot: tree.getRoot(),
      currentTimestamp: Math.floor(Date.now() / 1000),
      compliancePk: COMPLIANCE_PK,

      recipientB: bob_dleq.B,
      recipientP: bob_dleq.P,
      recipientProof: bob_dleq.pi,

      oldNote: depositPlain,
      oldSharedSecret: await deriveSharedSecret(ephemeralSk, COMPLIANCE_PK),
      oldNoteIndex: 0,
      oldNotePath: Array(32).fill(toFr(0n)),
      hashlockPreimage: toFr(0n),

      memoNote: memoPlain,
      memoEphemeralSk: toFr(12345n), // Alice's ephemeral for Bob

      changeNote: changePlain,
      changeEphemeralSk: toFr(67890n), // Alice's ephemeral for Change
    };

    const proof = await proveTransfer(inputs);

    // 5. Execute On-Chain
    await expect(
      darkPool.connect(alice).privateTransfer(proof.proof, proof.publicInputs),
    )
      .to.emit(darkPool, "NewPrivateMemo")
      .and.to.emit(darkPool, "NewNote") // Change note
      .and.to.emit(darkPool, "NullifierSpent");

    // 6. Verify State
    // Check Nullifier (Index 8 in Transfer layout)
    const nullifierHash = proof.publicInputs[8];
    expect(await darkPool.isNullifierSpent(nullifierHash)).to.equal(true);
  });

  it("Should prevent Double Transfer", async function () {
    const { darkPool, token, alice } = await loadFixture(deployDarkPoolFixture);
    const { depositPlain, ephemeralSk, commitment } = await makeDeposit(
      darkPool,
      token,
      alice,
      100n,
    );

    const tree = new LeanIMT(32);
    await tree.insert(commitment);
    const bob_dleq = await generateDLEQProof(123n, COMPLIANCE_PK);

    const inputs: TransferInputs = {
      merkleRoot: tree.getRoot(),
      currentTimestamp: Math.floor(Date.now() / 1000),
      compliancePk: COMPLIANCE_PK,
      recipientB: bob_dleq.B,
      recipientP: bob_dleq.P,
      recipientProof: bob_dleq.pi,
      oldNote: depositPlain,
      oldSharedSecret: await deriveSharedSecret(ephemeralSk, COMPLIANCE_PK),
      oldNoteIndex: 0,
      oldNotePath: Array(32).fill(toFr(0n)),
      hashlockPreimage: toFr(0n),
      memoNote: { ...depositPlain, value: toFr(50n) },
      memoEphemeralSk: toFr(1n),
      changeNote: { ...depositPlain, value: toFr(50n) },
      changeEphemeralSk: toFr(2n),
    };

    const proof = await proveTransfer(inputs);

    // First transfer ok
    await darkPool
      .connect(alice)
      .privateTransfer(proof.proof, proof.publicInputs);

    // Replay fails
    await expect(
      darkPool.connect(alice).privateTransfer(proof.proof, proof.publicInputs),
    ).to.be.revertedWithCustomError(darkPool, "NullifierAlreadySpent");
  });
});
