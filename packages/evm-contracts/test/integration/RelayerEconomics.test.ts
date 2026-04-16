/**
 * Relayer Economics Integration Test
 *
 * Full flow: relayer registers in NoxRegistry → user deposits to DarkPool →
 * relayer pays gas via payRelayer → reward deposited to NoxRewardPool →
 * admin distributes rewards to relayer.
 *
 * This is the first test that connects NoxRegistry + DarkPool + NoxRewardPool
 * in a single flow, proving the complete relayer incentive mechanism works.
 */
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
import { NoxRegistry__factory } from "../../typechain-types";

const BN254_FR_MODULUS =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

describe("Integration: Relayer Economics (NoxRegistry + DarkPool + NoxRewardPool)", function () {
  this.timeout(120_000);

  /**
   * Extended fixture: deploys DarkPool + NoxRegistry with a registered relayer.
   */
  async function deployFullStack() {
    const ctx = await deployDarkPoolFixture();
    const { deployer, relayer, token } = ctx;

    // Deploy NoxRegistry
    const RegistryFactory = (await ethers.getContractFactory(
      "NoxRegistry",
    )) as unknown as NoxRegistry__factory;
    const registry = await RegistryFactory.deploy(
      deployer.address,
      await token.getAddress(),
      0n, // minStake = 0 for testing
      86400n, // unstakeDelay = 1 day (contract minimum)
    );

    // Register the relayer as a privileged exit node
    const sphinxKey = ethers.randomBytes(32);
    const relayerUrl = "/ip4/127.0.0.1/tcp/9000";

    await registry.registerPrivileged(
      relayer.address,
      sphinxKey,
      relayerUrl,
      "",
      "",
      2, // role = Exit
    );

    return { ...ctx, registry, sphinxKey, relayerUrl };
  }

  it("full flow: register → deposit → payRelayer → reward deposited", async function () {
    const ctx = await loadFixture(deployFullStack);
    const { darkPool, token, rewardPool, relayer, registry, alice } = ctx;

    // 1. Verify relayer is registered on-chain
    const count = await registry.relayerCount();
    expect(count).to.equal(1n);
    const fingerprint = await registry.topologyFingerprint();
    expect(fingerprint).to.not.equal(ethers.ZeroHash);

    // 2. Alice deposits 100 tokens
    const {
      depositPlain: notePlaintext,
      ephemeralSk,
      commitment,
    } = await makeDeposit(darkPool, token, alice, 100n);

    // 3. Build Merkle tree
    const tree = new LeanIMT(32);
    await tree.insert(commitment);

    // 4. Relayer pays gas (10 tokens) using the deposited note
    const executionHash = toFr(
      BigInt(ethers.keccak256(ethers.toUtf8Bytes("batch_tx_payload"))) %
        BN254_FR_MODULUS,
    );

    const changeNote = {
      asset_id: notePlaintext.asset_id,
      value: toFr(90n), // 100 - 10 = 90 change
      secret: toFr(789n),
      nullifier: toFr(1011n),
      timelock: toFr(0n),
      hashlock: toFr(0n),
    };

    const gasInputs: GasPaymentInputs = {
      merkleRoot: tree.getRoot(),
      currentTimestamp: Math.floor(Date.now() / 1000),
      paymentValue: toFr(10n),
      paymentAssetId: notePlaintext.asset_id,
      relayerAddress: addressToFr(relayer.address),
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

    const gasProof = await proveGasPayment(gasInputs);

    const poolBalanceBefore = await token.balanceOf(
      await rewardPool.getAddress(),
    );

    const tx = await darkPool
      .connect(relayer)
      .payRelayer(
        gasProof.proof,
        gasProof.publicInputs.map((v) => ethers.zeroPadValue(v, 32)),
      );
    const receipt = await tx.wait();

    // 5. Verify GasPaymentProcessed event
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

    // 6. Verify reward deposited to NoxRewardPool
    const poolBalanceAfter = await token.balanceOf(
      await rewardPool.getAddress(),
    );
    expect(poolBalanceAfter - poolBalanceBefore).to.equal(10n);

    // 7. Admin distributes rewards to the relayer
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

    const {
      depositPlain: notePlaintext,
      ephemeralSk,
      commitment,
    } = await makeDeposit(darkPool, token, alice, 100n);

    const tree = new LeanIMT(32);
    await tree.insert(commitment);

    const executionHash = toFr(
      BigInt(ethers.keccak256(ethers.toUtf8Bytes("double_spend_test"))) %
        BN254_FR_MODULUS,
    );

    const changeNote = {
      asset_id: notePlaintext.asset_id,
      value: toFr(90n),
      secret: toFr(789n),
      nullifier: toFr(1011n),
      timelock: toFr(0n),
      hashlock: toFr(0n),
    };

    const gasInputs: GasPaymentInputs = {
      merkleRoot: tree.getRoot(),
      currentTimestamp: Math.floor(Date.now() / 1000),
      paymentValue: toFr(10n),
      paymentAssetId: notePlaintext.asset_id,
      relayerAddress: addressToFr(relayer.address),
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

    const gasProof = await proveGasPayment(gasInputs);
    const publicInputs = gasProof.publicInputs.map((v) =>
      ethers.zeroPadValue(v, 32),
    );

    // First use succeeds
    await darkPool.connect(relayer).payRelayer(gasProof.proof, publicInputs);

    // Second use with same nullifier reverts
    await expect(
      darkPool.connect(relayer).payRelayer(gasProof.proof, publicInputs),
    ).to.be.revertedWithCustomError(darkPool, "NullifierAlreadySpent");
  });

  it("reward pool tracks cumulative deposits from multiple gas payments", async function () {
    const ctx = await loadFixture(deployFullStack);
    const { darkPool, token, rewardPool, relayer, alice } = ctx;

    // Make 3 deposits
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

    // Pay gas from each deposit (5 tokens each = 15 total)
    for (let i = 0; i < 3; i++) {
      const executionHash = toFr(BigInt(i + 1));
      const changeNote = {
        asset_id: deposits[i]!.depositPlain.asset_id,
        value: toFr(45n), // 50 - 5
        secret: toFr(BigInt(100 + i)),
        nullifier: toFr(BigInt(200 + i)),
        timelock: toFr(0n),
        hashlock: toFr(0n),
      };

      const gasInputs: GasPaymentInputs = {
        merkleRoot: tree.getRoot(),
        currentTimestamp: Math.floor(Date.now() / 1000),
        paymentValue: toFr(5n),
        paymentAssetId: deposits[i]!.depositPlain.asset_id,
        relayerAddress: addressToFr(relayer.address),
        executionHash,
        compliancePk: COMPLIANCE_PK,
        oldNote: deposits[i]!.depositPlain,
        oldSharedSecret: await deriveSharedSecret(
          deposits[i]!.ephemeralSk,
          COMPLIANCE_PK,
        ),
        oldNoteIndex: i,
        oldNotePath: tree.getMerklePath(i),
        hashlockPreimage: toFr(0n),
        changeNote,
        changeEphemeralSk: toFr(BigInt(300 + i)),
      };

      const gasProof = await proveGasPayment(gasInputs);
      await darkPool
        .connect(relayer)
        .payRelayer(
          gasProof.proof,
          gasProof.publicInputs.map((v) => ethers.zeroPadValue(v, 32)),
        );
    }

    const poolBalanceAfter = await token.balanceOf(
      await rewardPool.getAddress(),
    );
    expect(poolBalanceAfter - poolBalanceBefore).to.equal(15n);
  });
});
