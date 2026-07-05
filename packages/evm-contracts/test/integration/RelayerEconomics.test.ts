/**
 * Relayer Economics Integration Test
 *
 * Full flow: relayer registers in NoxRegistry, user deposits to DarkPool, relayer pays gas via payRelayer,
 * reward deposited to NoxRewardPool, admin distributes rewards to relayer.
 */
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
import { toFr, addressToFr, LeanIMT } from "@hisoka/wallets";
import { proveGasPayment, GasPaymentInputs } from "@hisoka/prover";
import { NoxRegistry__factory } from "../../typechain-types";

const BN254_FR_MODULUS =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

describe("Integration: Relayer Economics (NoxRegistry + DarkPool + NoxRewardPool)", function () {
  this.timeout(120_000);

  async function deployFullStack() {
    const ctx = await deployDarkPoolFixture();
    const { deployer, relayer, token } = ctx;

    const RegistryFactory = (await ethers.getContractFactory(
      "NoxRegistry",
    )) as unknown as NoxRegistry__factory;
    const registry = await RegistryFactory.deploy(
      deployer.address,
      await token.getAddress(),
      ethers.parseEther("1"),
      86400n,
      ethers.parseEther("1"),
    );

    const sphinxKey = ethers.randomBytes(32);
    const relayerUrl = "/ip4/127.0.0.1/tcp/9000";

    await registry.registerPrivileged(
      relayer.address,
      sphinxKey,
      relayerUrl,
      "",
      "",
      2,
    );

    return { ...ctx, registry, sphinxKey, relayerUrl };
  }

  it("full flow: register -> deposit -> payRelayer -> reward deposited", async function () {
    const ctx = await loadFixture(deployFullStack);
    const {
      darkPool,
      token,
      rewardPool,
      mockNoxRegistry,
      relayer,
      registry,
      alice,
    } = ctx;
    const assetFr = addressToFr(await token.getAddress());

    const count = await registry.relayerCount();
    expect(count).to.equal(1n);
    const fingerprint = await registry.topologyFingerprint();
    expect(fingerprint).to.not.equal(ethers.ZeroHash);

    const dep = await makeDeposit(darkPool, token, alice, 100n);

    const executionHash = toFr(
      BigInt(ethers.keccak256(ethers.toUtf8Bytes("batch_tx_payload"))) %
        BN254_FR_MODULUS,
    );

    const change = await mintSelfNote(
      evenYEphemeral(888n),
      90n,
      dep.spendScalar,
      assetFr,
    );

    const gasInputs: GasPaymentInputs = {
      currentTimestamp: Math.floor(Date.now() / 1000),
      paymentValue: toFr(10n),
      paymentAssetId: assetFr,
      relayerAddress: addressToFr(relayer.address),
      executionHash,
      compliancePk: COMPLIANCE_PK,
      oldNote: dep.built.note,
      spendScalar: dep.spendScalar,
      oldNoteIndex: 0,
      oldNotePath: Array(32).fill(toFr(0n)),
      changeNote: change.note,
      changeEph: change.eph,
    };

    const gasProof = await proveGasPayment(gasInputs);

    const poolBalanceBefore = await token.balanceOf(
      await rewardPool.getAddress(),
    );

    const tx = await darkPool
      .connect(relayer)
      .payRelayer(gasProof.proof, gasProof.publicInputs);
    const receipt = await tx.wait();

    const gasEvent = receipt?.logs.find((log) => {
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
    expect(gasEvent).to.not.equal(undefined);

    const poolBalanceAfter = await token.balanceOf(
      await rewardPool.getAddress(),
    );
    expect(poolBalanceAfter - poolBalanceBefore).to.equal(10n);

    await mockNoxRegistry.setActive(relayer.address, true);
    const relayerBalanceBefore = await token.balanceOf(relayer.address);
    await rewardPool.distributeRewards(
      await token.getAddress(),
      [relayer.address],
      [10n],
    );
    const relayerBalanceAfter = await token.balanceOf(relayer.address);
    expect(relayerBalanceAfter - relayerBalanceBefore).to.equal(10n);
  });

  it("payRelayer nullifier prevents double-claiming the same note", async function () {
    const ctx = await loadFixture(deployFullStack);
    const { darkPool, token, relayer, alice } = ctx;
    const assetFr = addressToFr(await token.getAddress());

    const dep = await makeDeposit(darkPool, token, alice, 100n);

    const executionHash = toFr(
      BigInt(ethers.keccak256(ethers.toUtf8Bytes("double_spend_test"))) %
        BN254_FR_MODULUS,
    );

    const change = await mintSelfNote(
      evenYEphemeral(888n),
      90n,
      dep.spendScalar,
      assetFr,
    );

    const gasInputs: GasPaymentInputs = {
      currentTimestamp: Math.floor(Date.now() / 1000),
      paymentValue: toFr(10n),
      paymentAssetId: assetFr,
      relayerAddress: addressToFr(relayer.address),
      executionHash,
      compliancePk: COMPLIANCE_PK,
      oldNote: dep.built.note,
      spendScalar: dep.spendScalar,
      oldNoteIndex: 0,
      oldNotePath: Array(32).fill(toFr(0n)),
      changeNote: change.note,
      changeEph: change.eph,
    };

    const gasProof = await proveGasPayment(gasInputs);

    await darkPool
      .connect(relayer)
      .payRelayer(gasProof.proof, gasProof.publicInputs);

    await expect(
      darkPool.connect(relayer).payRelayer(gasProof.proof, gasProof.publicInputs),
    ).to.be.revertedWithCustomError(darkPool, "NullifierAlreadySpent");
  });

  it("reward pool tracks cumulative deposits from multiple gas payments", async function () {
    const ctx = await loadFixture(deployFullStack);
    const { darkPool, token, rewardPool, relayer, alice } = ctx;
    const assetFr = addressToFr(await token.getAddress());

    const deposits = [];
    for (let i = 0; i < 3; i++) {
      deposits.push(await makeDeposit(darkPool, token, alice, 50n));
    }

    const tree = new LeanIMT(32);
    for (const d of deposits) {
      await tree.insert(d.commitment);
    }

    const poolBalanceBefore = await token.balanceOf(
      await rewardPool.getAddress(),
    );

    for (let i = 0; i < 3; i++) {
      const executionHash = toFr(BigInt(i + 1));
      const change = await mintSelfNote(
        evenYEphemeral(BigInt(300 + i)),
        45n,
        deposits[i]!.spendScalar,
        assetFr,
      );

      const gasInputs: GasPaymentInputs = {
        currentTimestamp: Math.floor(Date.now() / 1000),
        paymentValue: toFr(5n),
        paymentAssetId: assetFr,
        relayerAddress: addressToFr(relayer.address),
        executionHash,
        compliancePk: COMPLIANCE_PK,
        oldNote: deposits[i]!.built.note,
        spendScalar: deposits[i]!.spendScalar,
        oldNoteIndex: i,
        oldNotePath: tree.getMerklePath(i),
        changeNote: change.note,
        changeEph: change.eph,
      };

      const gasProof = await proveGasPayment(gasInputs);
      await darkPool
        .connect(relayer)
        .payRelayer(gasProof.proof, gasProof.publicInputs);
    }

    const poolBalanceAfter = await token.balanceOf(
      await rewardPool.getAddress(),
    );
    expect(poolBalanceAfter - poolBalanceBefore).to.equal(15n);
  });
});
