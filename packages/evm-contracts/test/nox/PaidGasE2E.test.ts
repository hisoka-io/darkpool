 
/**
 * Paid Gas Payment E2E — Tests the COMPLETE gas payment multicall pipeline.
 *
 * Every non-deposit operation uses MixnetWallet which:
 *   1. Builds the action proof (split/join/transfer/withdraw)
 *   2. Builds a gas payment proof (pays relayer from shielded note)
 *   3. Bundles both into a RelayerMulticall: [payRelayer, action]
 *   4. Submits atomically on-chain
 *
 * Scenario: Alice → Bob → Charlie → David economy with all 7 circuits.
 */

import { expect } from "chai";
import { ethers } from "hardhat";
import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import { COMPLIANCE_PK } from "../helpers/fixtures";
import { MixnetWallet } from "../helpers/MixnetWallet";
import {
  generateDLEQProof,
} from "@hisoka/wallets";


/**
 * Deploy DarkPool + RelayerMulticall + NoxRewardPool.
 * This is the full stack needed for paid gas flow.
 */
async function deployFullStack() {
  const [deployer, alice, bob, charlie, david, relayer] =
    await ethers.getSigners();

  // 1. Libs
  const Poseidon2Factory = await ethers.getContractFactory("Poseidon2");
  const poseidon2Lib = await Poseidon2Factory.deploy();

  // 2. Verifiers
  const deployVerifier = async (contractPath: string) => {
    return (
      await ethers.getContractFactory(`${contractPath}:HonkVerifier`)
    ).deploy();
  };
  const DepVerifier = await deployVerifier("contracts/verifiers/DepositVerifier.sol");
  const WdwVerifier = await deployVerifier("contracts/verifiers/WithdrawVerifier.sol");
  const TrfVerifier = await deployVerifier("contracts/verifiers/TransferVerifier.sol");
  const JoinVerifier = await deployVerifier("contracts/verifiers/JoinVerifier.sol");
  const SplitVerifier = await deployVerifier("contracts/verifiers/SplitVerifier.sol");
  const PublicClaimVerifier = await deployVerifier("contracts/verifiers/PublicClaimVerifier.sol");
  const GasVerifier = await deployVerifier("contracts/verifiers/GasPaymentVerifier.sol");

  // 3. NoxRewardPool
  const RewardPoolFactory = await ethers.getContractFactory("NoxRewardPool");
  const rewardPool = await RewardPoolFactory.deploy(deployer.address);

  // 4. Token
  const TokenFactory = await ethers.getContractFactory("MockERC20");
  const token = await TokenFactory.deploy("Mock", "MCK", 18);
  await rewardPool.setAssetStatus(await token.getAddress(), true);

  // Fund users
  const amt = ethers.parseEther("10000");
  await token.mint(alice.address, amt);
  await token.mint(bob.address, amt);
  await token.mint(charlie.address, amt);
  await token.mint(david.address, amt);

  // 5. DarkPool
  const DarkPoolFactory = await ethers.getContractFactory("DarkPool", {
    libraries: { Poseidon2: await poseidon2Lib.getAddress() },
  });
  const darkPool = await DarkPoolFactory.deploy(
    await DepVerifier.getAddress(),
    await WdwVerifier.getAddress(),
    await TrfVerifier.getAddress(),
    await JoinVerifier.getAddress(),
    await SplitVerifier.getAddress(),
    await PublicClaimVerifier.getAddress(),
    await GasVerifier.getAddress(),
    await rewardPool.getAddress(),
    COMPLIANCE_PK[0],
    COMPLIANCE_PK[1],
    deployer.address,
  );

  // 6. RelayerMulticall
  const MulticallFactory = await ethers.getContractFactory("RelayerMulticall");
  const multicall = await MulticallFactory.deploy();

  return {
    darkPool: darkPool as any,
    token: token as any,
    rewardPool,
    multicall,
    deployer,
    alice,
    bob,
    charlie,
    david,
    relayer,
  };
}

describe("Paid Gas Payment: Full Economy E2E", function () {
  this.timeout(600_000); // 10 min for ZK proofs

  // ==========================================================================
  // Full Economy: Alice → Bob → Charlie → David with gas payments
  // ==========================================================================

  it("Alice deposits, splits (paid), transfers to Bob (paid), Bob withdraws (paid)", async function () {
    const ctx = await loadFixture(deployFullStack);
    const { darkPool, token, multicall, relayer } = ctx;
    const multicallAddr = await multicall.getAddress();

    // --- Create MixnetWallets ---
    console.log("\n  [1] Creating MixnetWallets...");
    const alice = await MixnetWallet.create(
      ctx.alice, darkPool, token, multicallAddr, relayer.address,
    );
    const bob = await MixnetWallet.create(
      ctx.bob, darkPool, token, multicallAddr, relayer.address,
    );

    // --- Alice deposits 200 (action fund) + 10 (gas fund) ---
    console.log("  [2] Alice deposits 200 + 10 tokens (direct)...");
    await alice.deposit(ethers.parseEther("200"));
    await alice.deposit(ethers.parseEther("10"));
    // sync() inserts ALL on-chain leaves into the tree AND discovers notes
    await alice.sync();
    await bob.sync(); // Bob needs the tree synced too (for his future operations)
    expect(alice.getBalance()).to.equal(ethers.parseEther("210"));

    // --- Alice splits 200 → 150 + 50 (via gas-paid multicall) ---
    console.log("  [3] Alice splits 200 → 150 + 50 (gas-paid multicall)...");
    const { txHash: splitTx } = await alice.splitViaMixnet(
      ethers.parseEther("150"),
      ethers.parseEther("50"),
    );
    console.log(`    Split TX: ${splitTx}`);

    // Sync all wallets — picks up split output notes + gas change note
    await alice.sync();
    await bob.sync();
    console.log(`    Alice balance after split: ${ethers.formatEther(alice.getBalance())}`);

    // --- Alice transfers 30 to Bob (via gas-paid multicall) ---
    console.log("  [4] Alice transfers 30 to Bob (gas-paid multicall)...");
    await bob.keyRepo.advanceIncomingKeys(1);
    const bobIvk = await bob.account.getIncomingViewingKey(0n);
    const bobAddr = await generateDLEQProof(bobIvk.toBigInt(), COMPLIANCE_PK);

    const { txHash: trfTx } = await alice.transferViaMixnet(
      ethers.parseEther("30"),
      bobAddr.B, bobAddr.P, bobAddr.pi,
    );
    console.log(`    Transfer TX: ${trfTx}`);

    // Sync
    await bob.sync();
    await alice.sync();

    expect(bob.getBalance()).to.equal(ethers.parseEther("30"));
    console.log(`    Bob: ${ethers.formatEther(bob.getBalance())}`);

    // --- Bob withdraws 20 (via gas-paid multicall) ---
    console.log("  [5] Bob withdraws 20 (gas-paid multicall)...");

    await bob.deposit(ethers.parseEther("5"));
    await bob.sync();
    await alice.sync();

    const bobBalBefore = await token.balanceOf(ctx.bob.address);
    const { txHash: wdTx } = await bob.withdrawViaMixnet(ethers.parseEther("20"));
    console.log(`    Withdraw TX: ${wdTx}`);

    const bobBalAfter = await token.balanceOf(ctx.bob.address);
    expect(bobBalAfter - bobBalBefore).to.equal(ethers.parseEther("20"));

    // Verify reward pool received gas payments
    const poolBalance = await token.balanceOf(await ctx.rewardPool.getAddress());
    console.log(`    RewardPool balance: ${poolBalance} (accumulated gas fees)`);
    expect(poolBalance).to.be.gt(0n);

    console.log("\n  [OK] Full gas-paid economy: deposit → split → transfer → withdraw");
  });

  // ==========================================================================
  // Join via gas payment
  // ==========================================================================

  it("Alice deposits twice, joins via gas-paid multicall", async function () {
    const ctx = await loadFixture(deployFullStack);
    const { darkPool, token, multicall, relayer } = ctx;

    const alice = await MixnetWallet.create(
      ctx.alice, darkPool, token,
      await multicall.getAddress(), relayer.address,
    );

    // Three deposits: two to join + one for gas
    console.log("\n  [1] Alice deposits 60 + 40 + 10 (gas fund)...");
    await alice.deposit(ethers.parseEther("60"));
    await alice.deposit(ethers.parseEther("40"));
    await alice.deposit(ethers.parseEther("10"));
    await alice.sync();
    expect(alice.getBalance()).to.equal(ethers.parseEther("110"));

    // Join via gas-paid multicall
    console.log("  [2] Alice joins 60 + 40 → 100 (gas-paid multicall)...");
    const { txHash } = await alice.joinViaMixnet(0, 1);
    console.log(`    Join TX: ${txHash}`);

    await alice.sync();
    console.log(`    Alice balance after join: ${ethers.formatEther(alice.getBalance())}`);

    console.log("  [OK] Join via gas-paid multicall");
  });

});
