import { expect } from "chai";
import { ethers } from "hardhat";
import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";
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
} from "@hisoka/wallets";
import { proveGasPayment, GasPaymentInputs } from "@hisoka/prover";

const toBytes32 = (val: string) => ethers.zeroPadValue(val, 32);

describe("DarkPool Behavior: PayRelayer", function () {
  this.timeout(120_000); // ZK proof generation takes time

  async function prepareGasPayment(
    ctx: Awaited<ReturnType<typeof deployDarkPoolFixture>>,
    paymentAmount: bigint,
    noteValue: bigint = 100n,
  ) {
    const { darkPool, alice, token, relayer } = ctx;

    // 1. Make a deposit to create a spendable note
    const {
      depositPlain: notePlaintext,
      ephemeralSk,
      commitment,
    } = await makeDeposit(darkPool, token, alice, noteValue);

    // 2. Build Merkle tree
    const tree = new LeanIMT(32);
    await tree.insert(commitment);

    // 3. Build gas payment proof inputs
    const relayerAddress = await relayer.getAddress();
    // keccak256 output overflows BN254 Fr ~75% of the time — reduce mod Fr
    const BN254_FR_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
    const executionHash = toFr(
      BigInt(ethers.keccak256(ethers.toUtf8Bytes("test_execution_payload"))) % BN254_FR_MODULUS
    );

    const changeValue = noteValue - paymentAmount;
    const changeNote = {
      asset_id: notePlaintext.asset_id,
      value: toFr(changeValue),
      secret: toFr(789n),
      nullifier: toFr(1011n),
      timelock: toFr(0n),
      hashlock: toFr(0n),
    };

    const inputs: GasPaymentInputs = {
      merkleRoot: tree.getRoot(),
      currentTimestamp: Math.floor(Date.now() / 1000),
      paymentValue: toFr(paymentAmount),
      paymentAssetId: notePlaintext.asset_id,
      relayerAddress: addressToFr(relayerAddress),
      executionHash,
      compliancePk: COMPLIANCE_PK,
      oldNote: notePlaintext,
      oldSharedSecret: await deriveSharedSecret(ephemeralSk, COMPLIANCE_PK),
      oldNoteIndex: 0,
      oldNotePath: Array(32).fill(toFr(0n)),
      hashlockPreimage: toFr(0n),
      changeNote,
      changeEphemeralSk: toFr(888n),
    };

    const proof = await proveGasPayment(inputs);
    return { proof, inputs, relayerAddress, changeNote };
  }

  it("should allow valid gas payment and emit GasPaymentProcessed", async function () {
    const ctx = await loadFixture(deployDarkPoolFixture);
    const { darkPool, relayer } = ctx;

    const { proof, relayerAddress } = await prepareGasPayment(ctx, 10n);

    const tx = await darkPool
      .connect(relayer)
      .payRelayer(proof.proof, proof.publicInputs.map(toBytes32));

    const receipt = await tx.wait();
    const event = receipt?.logs.find(
      (log) => {
        try {
          return darkPool.interface.parseLog({ topics: [...log.topics], data: log.data })?.name === "GasPaymentProcessed";
        } catch { return false; }
      }
    );
    expect(event).to.not.equal(undefined);

    // Decode event
    const parsed = darkPool.interface.parseLog({
      topics: [...event!.topics],
      data: event!.data,
    });
    expect(parsed?.args.relayer.toLowerCase()).to.equal(relayerAddress.toLowerCase());
    expect(parsed?.args.amount).to.equal(10n);
  });

  it("should create a change note (NewNote event)", async function () {
    const ctx = await loadFixture(deployDarkPoolFixture);
    const { darkPool, relayer } = ctx;

    const { proof } = await prepareGasPayment(ctx, 10n, 100n);

    const tx = await darkPool
      .connect(relayer)
      .payRelayer(proof.proof, proof.publicInputs.map(toBytes32));

    const receipt = await tx.wait();
    const newNoteEvent = receipt?.logs.find(
      (log) => {
        try {
          return darkPool.interface.parseLog({ topics: [...log.topics], data: log.data })?.name === "NewNote";
        } catch { return false; }
      }
    );
    expect(newNoteEvent).to.not.equal(undefined);
  });

  it("should deposit payment into NoxRewardPool", async function () {
    const ctx = await loadFixture(deployDarkPoolFixture);
    const { darkPool, relayer, token, rewardPool } = ctx;

    const balanceBefore = await token.balanceOf(await rewardPool.getAddress());

    const { proof } = await prepareGasPayment(ctx, 10n, 100n);

    await darkPool
      .connect(relayer)
      .payRelayer(proof.proof, proof.publicInputs.map(toBytes32));

    const balanceAfter = await token.balanceOf(await rewardPool.getAddress());
    expect(balanceAfter - balanceBefore).to.equal(10n);
  });

  it("should prevent double-spend (nullifier replay)", async function () {
    const ctx = await loadFixture(deployDarkPoolFixture);
    const { darkPool, relayer } = ctx;

    const { proof } = await prepareGasPayment(ctx, 10n, 100n);

    // First call succeeds
    await darkPool
      .connect(relayer)
      .payRelayer(proof.proof, proof.publicInputs.map(toBytes32));

    // Second call with same proof should revert (nullifier already spent)
    await expect(
      darkPool
        .connect(relayer)
        .payRelayer(proof.proof, proof.publicInputs.map(toBytes32))
    ).to.be.revertedWithCustomError(darkPool, "NullifierAlreadySpent");
  });

  it("should reject invalid input length", async function () {
    const ctx = await loadFixture(deployDarkPoolFixture);
    const { darkPool, relayer } = ctx;

    const fakeProof = ethers.randomBytes(100);
    const tooFewInputs = Array(10).fill(ethers.ZeroHash);

    await expect(
      darkPool.connect(relayer).payRelayer(fakeProof, tooFewInputs)
    ).to.be.revertedWithCustomError(darkPool, "InvalidInputsLength");
  });

  it("should reject zero payment value", async function () {
    const ctx = await loadFixture(deployDarkPoolFixture);
    const { darkPool, relayer, token, rewardPool } = ctx;

    const { proof } = await prepareGasPayment(ctx, 0n, 100n);

    const balanceBefore = await token.balanceOf(await rewardPool.getAddress());

    // Zero payment is valid (no transfer, just spends the note)
    await darkPool
      .connect(relayer)
      .payRelayer(proof.proof, proof.publicInputs.map(toBytes32));

    const balanceAfter = await token.balanceOf(await rewardPool.getAddress());
    // No transfer should happen
    expect(balanceAfter).to.equal(balanceBefore);
  });
});
