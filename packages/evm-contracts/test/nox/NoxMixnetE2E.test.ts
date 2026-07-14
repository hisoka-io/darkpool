/* eslint-disable @typescript-eslint/no-unused-expressions */
/**
 * NOX Mixnet E2E: wallet SDK + ZK proofs + mixnet transport + on-chain verification.
 *
 * Prerequisites:
 *   - Anvil running: anvil --port 8545 --silent
 *   - nox mesh: cargo run -p nox-sim --bin nox_mesh_server --features dev-node --release -- --nodes 5 --data-dir /tmp/nox_mesh --base-port 14000 --anvil-port 8545 --mix-delay-ms 0
 *   Or set NOX_MESH_AUTO=1 to have the test manage infra automatically.
 */

import { expect } from "chai";
import { ethers } from "hardhat";
import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import { deployDarkPoolFixture } from "../helpers/fixtures";
import { TestWallet } from "../helpers/TestWallet";
import { publicKey } from "@hisoka/wallets";
import { NoxClient } from "@hisoka-io/nox-client";
import * as fs from "node:fs";

const MESH_INFO_PATH =
  process.env["MESH_INFO_PATH"] ?? "/tmp/nox_mesh/mesh_info.json";

interface MeshInfo {
  entry_url: string;
  seed_url: string;
  node_count: number;
  anvil_rpc?: string;
}

function readMeshInfo(): MeshInfo | null {
  try {
    const raw = JSON.parse(fs.readFileSync(MESH_INFO_PATH, "utf-8"));
    // Derive seed_url from node 0's metrics port when not present
    const seedUrl =
      raw.seed_url ??
      (raw.nodes?.[0]
        ? `http://127.0.0.1:${raw.nodes[0].metrics_port}`
        : undefined);
    return {
      entry_url: raw.entry_url,
      seed_url: seedUrl,
      node_count: raw.node_count,
      anvil_rpc: raw.anvil_rpc_url,
    };
  } catch {
    return null;
  }
}

async function createNoxClient(meshInfo: MeshInfo): Promise<NoxClient> {
  const client = await NoxClient.connect({
    seeds: [meshInfo.seed_url],
    powDifficulty: 0,
    timeoutMs: 30_000,
    surbsPerRequest: 5,
    dangerouslySkipFingerprintCheck: true, // local test mesh has all-zero fingerprint
  });
  return client;
}

describe("NOX Mixnet: Full DeFi E2E", function () {
  this.timeout(600_000); // 10 min -- ZK proofs + mixnet latency

  let meshInfo: MeshInfo | null;
  let noxClient: any;

  before(async function () {
    meshInfo = readMeshInfo();
    if (!meshInfo) {
      console.log(
        `  [SKIP] No mesh_info at ${MESH_INFO_PATH}. Start nox_mesh_server first.`,
      );
      this.skip();
      return;
    }

    console.log(
      `  Mesh: ${meshInfo.node_count} nodes, entry at ${meshInfo.entry_url}`,
    );
    noxClient = await createNoxClient(meshInfo);
    console.log("  NoxClient connected.");
  });

  after(async function () {
    if (noxClient) {
      noxClient.disconnect();
    }
  });

  it("Alice deposits, splits, transfers to Bob, Bob withdraws — all via mixnet", async function () {
    const { darkPool, token, alice, bob } = await loadFixture(
      deployDarkPoolFixture,
    );
    console.log("\n  [1] Bootstrapping wallets...");
    const aliceWallet = await TestWallet.create(alice, darkPool, token);
    const bobWallet = await TestWallet.create(bob, darkPool, token);

    console.log("  [2] Alice deposits 100 tokens (direct)...");
    const DEPOSIT_AMT = ethers.parseEther("100");
    const depRes = await aliceWallet.deposit(DEPOSIT_AMT);
    await bobWallet.syncTree(depRes.commitment);
    await aliceWallet.sync();
    expect(aliceWallet.getBalance()).to.equal(DEPOSIT_AMT);

    console.log("  [3] Alice splits 100 → 60 + 40 (via mixnet)...");
    const SPLIT_A = ethers.parseEther("60");
    const SPLIT_B = ethers.parseEther("40");

    const split = await aliceWallet.split(SPLIT_A, SPLIT_B);
    await aliceWallet.syncTree(split.commitment1);
    await aliceWallet.syncTree(split.commitment2);
    await bobWallet.syncTree(split.commitment1);
    await bobWallet.syncTree(split.commitment2);

    await aliceWallet.sync();
    console.log(
      `    Alice balance after split: ${ethers.formatEther(aliceWallet.getBalance())}`,
    );
    // 60 + 40 = 100: same total across two notes
    expect(aliceWallet.getBalance()).to.equal(DEPOSIT_AMT);

    console.log("  [4] Alice transfers 30 to Bob (via mixnet)...");
    const TRANSFER_AMT = ethers.parseEther("30");

    // Spends Alice's 60-token note from the split
    const bobRecv = await bobWallet.getReceiveAddress();
    const trf = await aliceWallet.transfer(TRANSFER_AMT, bobRecv.inPub);

    await bobWallet.syncTree(trf.memoCommitment);
    await bobWallet.syncTree(trf.changeCommitment);
    await aliceWallet.syncTree(trf.memoCommitment);
    await aliceWallet.syncTree(trf.changeCommitment);

    await bobWallet.sync();
    await aliceWallet.sync();

    expect(bobWallet.getBalance()).to.equal(TRANSFER_AMT);
    expect(aliceWallet.getBalance()).to.equal(DEPOSIT_AMT - TRANSFER_AMT);
    console.log(
      `    Bob: ${ethers.formatEther(bobWallet.getBalance())}, Alice: ${ethers.formatEther(aliceWallet.getBalance())}`,
    );

    console.log("  [5] Bob withdraws 20 (via mixnet)...");
    const WITHDRAW_AMT = ethers.parseEther("20");

    const bobBalBefore = await token.balanceOf(bob.address);
    await bobWallet.withdraw(WITHDRAW_AMT);
    const bobBalAfter = await token.balanceOf(bob.address);

    expect(bobBalAfter - bobBalBefore).to.equal(WITHDRAW_AMT);
    console.log(
      `    Bob on-chain balance increased by ${ethers.formatEther(WITHDRAW_AMT)}`,
    );

    await bobWallet.sync();
    expect(bobWallet.getBalance()).to.equal(TRANSFER_AMT - WITHDRAW_AMT);

    console.log(
      "\n  [OK] Basic DeFi flow complete: deposit → split → transfer → withdraw",
    );
  });

  it("Alice deposits twice, joins both notes into one", async function () {
    const { darkPool, token, alice } = await loadFixture(deployDarkPoolFixture);

    const aliceWallet = await TestWallet.create(alice, darkPool, token);

    console.log("\n  [1] Alice deposits 50 + 30...");
    const dep1 = await aliceWallet.deposit(ethers.parseEther("50"));
    const dep2 = await aliceWallet.deposit(ethers.parseEther("30"));

    await aliceWallet.syncTree(dep1.commitment);
    await aliceWallet.syncTree(dep2.commitment);
    await aliceWallet.sync();

    expect(aliceWallet.getBalance()).to.equal(ethers.parseEther("80"));
    const notes = aliceWallet.utxoRepo.getUnspentNotes();
    expect(notes.length).to.equal(2);

    console.log("  [2] Alice joins 50 + 30 → 80...");
    const join = await aliceWallet.join();
    await aliceWallet.syncTree(join.commitment);
    await aliceWallet.sync();

    expect(aliceWallet.getBalance()).to.equal(ethers.parseEther("80"));
    console.log("  [OK] Join complete: 50 + 30 → 80");
  });

  it("should query chain state through the mixnet", async function () {
    // This test only works when the mesh exit nodes can reach the same chain (external Anvil).
    // Hardhat in-memory chain is not accessible from nox exit nodes.
    // We verify the NoxClient RPC methods work, even if exit nodes return connection errors.
    console.log("\n  [1] Querying chain state via mixnet...");

    try {
      const chainId = await noxClient.rpcCall("eth_chainId", []);
      expect(chainId).to.exist;
      console.log(`    chainId: ${chainId}`);

      const blockNum = await noxClient.rpcCall("eth_blockNumber", []);
      expect(blockNum).to.exist;
      console.log(`    blockNumber: ${blockNum}`);

      const [deployer] = await ethers.getSigners();
      const balance = await noxClient.rpcCall("eth_getBalance", [
        deployer.address,
        "latest",
      ]);
      expect(balance).to.exist;
      console.log(`    deployer balance: ${balance}`);

      const gasPrice = await noxClient.rpcCall("eth_gasPrice", []);
      expect(gasPrice).to.exist;
      console.log(`    gasPrice: ${gasPrice}`);

      const block = await noxClient.rpcCall("eth_getBlockByNumber", [
        "latest",
        false,
      ]);
      expect(block).to.exist;
      console.log(`    latest block exists: true`);

      console.log("  [OK] All chain queries via mixnet succeeded");
    } catch (err: any) {
      if (err.message?.includes("Connection refused")) {
        console.log(
          "  [SKIP] Exit nodes cannot reach Anvil (hardhat in-memory mode)",
        );
        this.skip();
      } else {
        throw err;
      }
    }
  });

  it("should handle multiple token types", async function () {
    const { darkPool, token, alice, bob } = await loadFixture(
      deployDarkPoolFixture,
    );
    const tokenAddr = await token.getAddress();

    console.log("\n  [1] Deploying second token (USDC mock)...");
    const Token2Factory = await ethers.getContractFactory("MockERC20");
    const token2 = await Token2Factory.deploy("Mock USDC", "MUSDC", 6);
    const token2Addr = await token2.getAddress();
    await token2.mint(alice.address, 1_000_000n * 10n ** 6n); // 1M USDC

    const aliceWallet = await TestWallet.create(alice, darkPool, token);
    const bobWallet = await TestWallet.create(bob, darkPool, token);

    console.log("  [2] Alice deposits 50 Token1...");
    const dep1 = await aliceWallet.deposit(ethers.parseEther("50"));
    await bobWallet.syncTree(dep1.commitment);
    await aliceWallet.sync();

    console.log("  [3] Alice deposits 100 Token2 (USDC)...");
    const dep2 = await aliceWallet.deposit(100n * 10n ** 6n, token2Addr);
    await bobWallet.syncTree(dep2.commitment);
    await aliceWallet.sync();

    const bal1 = aliceWallet.getBalance(tokenAddr);
    const bal2 = aliceWallet.getBalance(token2Addr);
    expect(bal1).to.equal(ethers.parseEther("50"));
    expect(bal2).to.equal(100n * 10n ** 6n);
    console.log(
      `    Alice: ${ethers.formatEther(bal1)} Token1, ${Number(bal2) / 1e6} Token2`,
    );

    console.log("  [4] Alice transfers 20 Token1 to Bob...");
    const bobRecv = await bobWallet.getReceiveAddress();
    const trf = await aliceWallet.transfer(
      ethers.parseEther("20"),
      bobRecv.inPub,
      tokenAddr,
    );

    await bobWallet.syncTree(trf.memoCommitment);
    await bobWallet.syncTree(trf.changeCommitment);
    await bobWallet.sync();
    await aliceWallet.sync();

    expect(bobWallet.getBalance(tokenAddr)).to.equal(ethers.parseEther("20"));
    expect(aliceWallet.getBalance(tokenAddr)).to.equal(ethers.parseEther("30"));
    expect(aliceWallet.getBalance(token2Addr)).to.equal(100n * 10n ** 6n);

    console.log("  [OK] Multi-asset: two tokens managed independently");
  });

  it("Alice public-transfers to Charlie, Charlie claims via mixnet", async function () {
    const { darkPool, token, alice, charlie } = await loadFixture(
      deployDarkPoolFixture,
    );
    const tokenAddr = await token.getAddress();

    const aliceWallet = await TestWallet.create(alice, darkPool, token);
    const charlieWallet = await TestWallet.create(charlie, darkPool, token);

    console.log("\n  [1] Alice deposits 100...");
    const dep = await aliceWallet.deposit(ethers.parseEther("100"));
    await charlieWallet.syncTree(dep.commitment);
    await aliceWallet.sync();

    console.log("  [2] Alice public-transfers 25 to Charlie...");
    const AMOUNT = ethers.parseEther("25");

    // The incoming key doubles as the claim key: its pubkey is the memo owner.
    const charlieClaimSk = await charlieWallet.account.getIncomingKey(0n);
    const charlieClaimPub = publicKey(charlieClaimSk);

    const salt = 12345n;
    const timelock = 0n;

    await token.connect(alice).approve(await darkPool.getAddress(), AMOUNT);
    const ptTx = await darkPool
      .connect(alice)
      .publicTransfer(
        charlieClaimPub[0],
        charlieClaimPub[1],
        tokenAddr,
        AMOUNT,
        timelock,
        salt,
      );
    const ptReceipt = await ptTx.wait();

    const memoLog = ptReceipt!.logs.find(
      (l: any) => l.fragment?.name === "NewPublicMemo",
    );
    const memoArgs = (memoLog as any).args;

    console.log("  [3] Charlie claims the public memo...");

    await charlieWallet.claimPublic(
      {
        memoId: memoArgs.memoId,
        ownerX: charlieClaimPub[0],
        ownerY: charlieClaimPub[1],
        asset: memoArgs.asset,
        value: memoArgs.value,
        timelock: memoArgs.timelock,
        salt: memoArgs.salt,
      },
      charlieClaimSk,
    );
    await charlieWallet.sync();

    expect(charlieWallet.getBalance()).to.equal(AMOUNT);
    console.log(`    Charlie claimed ${ethers.formatEther(AMOUNT)} tokens`);
    console.log("  [OK] Public transfer + claim flow complete");
  });

  it("Alice and Bob operate concurrently via mixnet", async function () {
    const { darkPool, token, alice, bob } = await loadFixture(
      deployDarkPoolFixture,
    );

    const aliceWallet = await TestWallet.create(alice, darkPool, token);
    const bobWallet = await TestWallet.create(bob, darkPool, token);

    console.log("\n  [1] Alice + Bob deposit concurrently...");
    const [depA, depB] = await Promise.all([
      aliceWallet.deposit(ethers.parseEther("50")),
      bobWallet.deposit(ethers.parseEther("50")),
    ]);

    await aliceWallet.syncTree(depA.commitment);
    await aliceWallet.syncTree(depB.commitment);
    await bobWallet.syncTree(depA.commitment);
    await bobWallet.syncTree(depB.commitment);

    await Promise.all([aliceWallet.sync(), bobWallet.sync()]);

    expect(aliceWallet.getBalance()).to.equal(ethers.parseEther("50"));
    expect(bobWallet.getBalance()).to.equal(ethers.parseEther("50"));

    console.log("  [2] Alice + Bob withdraw 10 each concurrently...");
    const aliceBalBefore = await token.balanceOf(alice.address);
    const bobBalBefore = await token.balanceOf(bob.address);

    await Promise.all([
      aliceWallet.withdraw(ethers.parseEther("10")),
      bobWallet.withdraw(ethers.parseEther("10")),
    ]);

    const aliceBalAfter = await token.balanceOf(alice.address);
    const bobBalAfter = await token.balanceOf(bob.address);

    expect(aliceBalAfter - aliceBalBefore).to.equal(ethers.parseEther("10"));
    expect(bobBalAfter - bobBalBefore).to.equal(ethers.parseEther("10"));

    console.log(
      "  [OK] Concurrent operations: both users operated in parallel",
    );
  });

  it("should discover notes via eth_getLogs through mixnet", async function () {
    console.log("\n  [1] Querying DarkPool events via mixnet...");

    try {
      const { darkPool, token, alice } = await loadFixture(
        deployDarkPoolFixture,
      );
      const darkPoolAddr = await darkPool.getAddress();

      const aliceWallet = await TestWallet.create(alice, darkPool, token);
      await aliceWallet.deposit(ethers.parseEther("10"));

      // Hex block numbers are required for range validation
      const depositTopic = ethers.id("NoteCreated(bytes32)");
      const logs = await noxClient.rpcCall("eth_getLogs", [
        {
          address: darkPoolAddr,
          topics: [depositTopic],
          fromBlock: "0x0",
          toBlock: "0x100",
        },
      ]);

      expect(logs).to.exist;
      console.log(
        `    Found ${Array.isArray(logs) ? logs.length : "?"} NoteCreated events via mixnet`,
      );
      console.log("  [OK] Event scanning via mixnet works");
    } catch (err: any) {
      if (err.message?.includes("Connection refused")) {
        console.log(
          "  [SKIP] Exit nodes cannot reach Anvil (hardhat in-memory mode)",
        );
        this.skip();
      } else {
        throw err;
      }
    }
  });
});
