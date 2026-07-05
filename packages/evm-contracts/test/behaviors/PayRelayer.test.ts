import { expect } from "chai";
import { ethers } from "hardhat";
import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import {
  deployDarkPoolFixture,
  makeDeposit,
  mintSelfNote,
  evenYEphemeral,
  COMPLIANCE_PK,
} from "../helpers/fixtures";
import { toFr, addressToFr } from "@hisoka/wallets";
import { proveGasPayment, GasPaymentInputs } from "@hisoka/prover";

const BN254_FR_MODULUS =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

describe("DarkPool Behavior: PayRelayer", function () {
  this.timeout(120_000);

  async function prepareGasPayment(
    ctx: Awaited<ReturnType<typeof deployDarkPoolFixture>>,
    paymentAmount: bigint,
    noteValue: bigint = 100n,
  ) {
    const { darkPool, alice, token, relayer } = ctx;
    const assetFr = addressToFr(await token.getAddress());

    const dep = await makeDeposit(darkPool, token, alice, noteValue);

    const relayerAddress = await relayer.getAddress();
    const executionHash = toFr(
      BigInt(ethers.keccak256(ethers.toUtf8Bytes("test_execution_payload"))) %
        BN254_FR_MODULUS,
    );

    const change = await mintSelfNote(
      evenYEphemeral(888n),
      noteValue - paymentAmount,
      dep.spendScalar,
      assetFr,
    );

    const inputs: GasPaymentInputs = {
      currentTimestamp: Math.floor(Date.now() / 1000),
      paymentValue: toFr(paymentAmount),
      paymentAssetId: assetFr,
      relayerAddress: addressToFr(relayerAddress),
      executionHash,
      compliancePk: COMPLIANCE_PK,
      oldNote: dep.built.note,
      spendScalar: dep.spendScalar,
      oldNoteIndex: 0,
      oldNotePath: Array(32).fill(toFr(0n)),
      changeNote: change.note,
      changeEph: change.eph,
    };

    const proof = await proveGasPayment(inputs);
    return { proof, inputs, relayerAddress };
  }

  it("should allow valid gas payment and emit GasPaymentProcessed", async function () {
    const ctx = await loadFixture(deployDarkPoolFixture);
    const { darkPool, relayer } = ctx;

    const { proof, relayerAddress } = await prepareGasPayment(ctx, 10n);

    const tx = await darkPool
      .connect(relayer)
      .payRelayer(proof.proof, proof.publicInputs);

    const receipt = await tx.wait();
    const event = receipt?.logs.find((log) => {
      try {
        return (
          darkPool.interface.parseLog({
            topics: [...log.topics],
            data: log.data,
          })?.name === "GasPaymentProcessed"
        );
      } catch {
        return false;
      }
    });
    expect(event).to.not.equal(undefined);

    const parsed = darkPool.interface.parseLog({
      topics: [...event!.topics],
      data: event!.data,
    });
    expect(parsed?.args.relayer.toLowerCase()).to.equal(
      relayerAddress.toLowerCase(),
    );
    expect(parsed?.args.amount).to.equal(10n);
  });

  it("should create a change note (NewNote event)", async function () {
    const ctx = await loadFixture(deployDarkPoolFixture);
    const { darkPool, relayer } = ctx;

    const { proof } = await prepareGasPayment(ctx, 10n, 100n);

    const tx = await darkPool
      .connect(relayer)
      .payRelayer(proof.proof, proof.publicInputs);

    const receipt = await tx.wait();
    const newNoteEvent = receipt?.logs.find((log) => {
      try {
        return (
          darkPool.interface.parseLog({
            topics: [...log.topics],
            data: log.data,
          })?.name === "NewNote"
        );
      } catch {
        return false;
      }
    });
    expect(newNoteEvent).to.not.equal(undefined);
  });

  it("should deposit payment into NoxRewardPool", async function () {
    const ctx = await loadFixture(deployDarkPoolFixture);
    const { darkPool, relayer, token, rewardPool } = ctx;

    const balanceBefore = await token.balanceOf(await rewardPool.getAddress());

    const { proof } = await prepareGasPayment(ctx, 10n, 100n);

    await darkPool.connect(relayer).payRelayer(proof.proof, proof.publicInputs);

    const balanceAfter = await token.balanceOf(await rewardPool.getAddress());
    expect(balanceAfter - balanceBefore).to.equal(10n);
  });

  it("should prevent double-spend (nullifier replay)", async function () {
    const ctx = await loadFixture(deployDarkPoolFixture);
    const { darkPool, relayer } = ctx;

    const { proof } = await prepareGasPayment(ctx, 10n, 100n);

    await darkPool.connect(relayer).payRelayer(proof.proof, proof.publicInputs);

    await expect(
      darkPool.connect(relayer).payRelayer(proof.proof, proof.publicInputs),
    ).to.be.revertedWithCustomError(darkPool, "NullifierAlreadySpent");
  });

  it("should reject invalid input length", async function () {
    const ctx = await loadFixture(deployDarkPoolFixture);
    const { darkPool, relayer } = ctx;

    const fakeProof = ethers.randomBytes(100);
    const tooFewInputs = Array(10).fill(ethers.ZeroHash);

    await expect(
      darkPool.connect(relayer).payRelayer(fakeProof, tooFewInputs),
    ).to.be.revertedWithCustomError(darkPool, "InvalidInputsLength");
  });

  it("should reject zero payment value", async function () {
    const ctx = await loadFixture(deployDarkPoolFixture);
    const { darkPool, relayer, token, rewardPool } = ctx;

    const { proof } = await prepareGasPayment(ctx, 0n, 100n);

    const balanceBefore = await token.balanceOf(await rewardPool.getAddress());

    await darkPool.connect(relayer).payRelayer(proof.proof, proof.publicInputs);

    const balanceAfter = await token.balanceOf(await rewardPool.getAddress());
    expect(balanceAfter).to.equal(balanceBefore);
  });
});
