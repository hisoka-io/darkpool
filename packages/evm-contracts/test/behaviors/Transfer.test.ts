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
  computeOwner,
  signSpendBinding,
} from "@hisoka/wallets";
import { proveTransfer, TransferInputs } from "@hisoka/prover";
import { Base8, mulPointEscalar } from "@zk-kit/baby-jubjub";

// Build a recipient spend-binding bundle from a viewing-key scalar (bobSk) and a
// chosen spend-key scalar. The circuit checks Poseidon2(S) == recipientOwner,
// memo.owner == recipientOwner, and the Schnorr binding of S to B = bobSk*G.
async function buildRecipientBinding(bobSk: bigint, bobNk: bigint) {
  const S = mulPointEscalar(Base8, bobNk);
  const owner = await computeOwner(S);
  const { R, s } = await signSpendBinding(bobSk, S, bobNk);
  return { owner, S, bindR: R, bindS: toFr(s) };
}

describe("DarkPool Behavior: Private Transfer", function () {
  it("should execute a valid transfer from Alice to Bob", async function () {
    const { darkPool, token, alice } = await loadFixture(deployDarkPoolFixture);

    // 1. Setup: Alice deposits 100
    const { depositPlain, ephemeralSk, commitment, nk } = await makeDeposit(
      darkPool,
      token,
      alice,
      100n,
    );

    // 2. Bob generates his "Hisoka Address" (DLEQ params) + spend binding
    const bob_sk = 555n;
    const bob_dleq = await generateDLEQProof(bob_sk, COMPLIANCE_PK);
    const bob = await buildRecipientBinding(bob_sk, 777n);

    // 3. Reconstruct tree (stand-in for Alice's wallet sync)
    const tree = new LeanIMT(32);
    await tree.insert(commitment);

    // 4. Prepare transfer
    const transferValue = 40n;
    const changeValue = 60n;

    const memoPlain: NotePlaintext = {
      asset_id: depositPlain.asset_id,
      value: toFr(transferValue),
      secret: toFr(0n), // Standard Memo dummy
      owner: bob.owner, // memo note belongs to the recipient
      timelock: toFr(0n),
      hashlock: toFr(0n),
    };

    const changePlain: NotePlaintext = {
      asset_id: depositPlain.asset_id,
      value: toFr(changeValue),
      secret: toFr(999n),
      owner: depositPlain.owner, // change returns to Alice
      timelock: toFr(0n),
      hashlock: toFr(0n),
    };

    const inputs: TransferInputs = {
      merkleRoot: tree.getRoot(),
      currentTimestamp: Math.floor(Date.now() / 1000),
      compliancePk: COMPLIANCE_PK,

      recipientB: bob_dleq.B,
      recipientP: bob_dleq.P,
      recipientOwner: bob.owner,
      recipientProof: bob_dleq.pi,
      recipientS: bob.S,
      bindR: bob.bindR,
      bindS: bob.bindS,

      oldNote: depositPlain,
      oldSharedSecret: await deriveSharedSecret(ephemeralSk, COMPLIANCE_PK),
      nk,
      oldNoteIndex: 0,
      oldNotePath: Array(32).fill(toFr(0n)),
      hashlockPreimage: toFr(0n),

      memoNote: memoPlain,
      memoEphemeralSk: toFr(12345n), // Alice's ephemeral for Bob

      changeNote: changePlain,
      changeEphemeralSk: toFr(67890n), // Alice's ephemeral for Change
    };

    const proof = await proveTransfer(inputs);

    await expect(
      darkPool.connect(alice).privateTransfer(proof.proof, proof.publicInputs),
    )
      .to.emit(darkPool, "NewPrivateMemo")
      .and.to.emit(darkPool, "NewNote") // Change note
      .and.to.emit(darkPool, "NullifierSpent");

    // Nullifier is index 9 in the transfer public-input layout
    const nullifierHash = proof.publicInputs[9];
    expect(await darkPool.isNullifierSpent(nullifierHash)).to.equal(true);
  });

  it("Should prevent Double Transfer", async function () {
    const { darkPool, token, alice } = await loadFixture(deployDarkPoolFixture);
    const { depositPlain, ephemeralSk, commitment, nk } = await makeDeposit(
      darkPool,
      token,
      alice,
      100n,
    );

    const tree = new LeanIMT(32);
    await tree.insert(commitment);
    const bob_sk = 123n;
    const bob_dleq = await generateDLEQProof(bob_sk, COMPLIANCE_PK);
    const bob = await buildRecipientBinding(bob_sk, 456n);

    const inputs: TransferInputs = {
      merkleRoot: tree.getRoot(),
      currentTimestamp: Math.floor(Date.now() / 1000),
      compliancePk: COMPLIANCE_PK,
      recipientB: bob_dleq.B,
      recipientP: bob_dleq.P,
      recipientOwner: bob.owner,
      recipientProof: bob_dleq.pi,
      recipientS: bob.S,
      bindR: bob.bindR,
      bindS: bob.bindS,
      oldNote: depositPlain,
      oldSharedSecret: await deriveSharedSecret(ephemeralSk, COMPLIANCE_PK),
      nk,
      oldNoteIndex: 0,
      oldNotePath: Array(32).fill(toFr(0n)),
      hashlockPreimage: toFr(0n),
      memoNote: { ...depositPlain, value: toFr(50n), owner: bob.owner },
      memoEphemeralSk: toFr(1n),
      changeNote: { ...depositPlain, value: toFr(50n) },
      changeEphemeralSk: toFr(2n),
    };

    const proof = await proveTransfer(inputs);

    await darkPool
      .connect(alice)
      .privateTransfer(proof.proof, proof.publicInputs);

    // Replay must fail (nullifier already spent)
    await expect(
      darkPool.connect(alice).privateTransfer(proof.proof, proof.publicInputs),
    ).to.be.revertedWithCustomError(darkPool, "NullifierAlreadySpent");
  });
});
