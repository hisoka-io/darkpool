/**
 * Live ZK Traffic Generator -- Real Noir ZK proofs through live NOX mixnet.
 *
 * Phase 1: Deposit tokens (user signs, broadcasts via mixnet) -- 2 deposits
 * Phase 2: Split via paid multicall (exit node submits, earns gas payment)
 *
 * Usage:
 *   cd darkpool-v2/packages/evm-contracts
 *   npx tsx test/nox/live_zk_traffic.ts
 */

import { webcrypto } from "node:crypto";
if (typeof globalThis.crypto === "undefined")
  (globalThis as unknown as { crypto: unknown }).crypto = webcrypto;

import { ethers } from "ethers";
import { NoxClient } from "@hisoka-io/nox-client";
import {
  toFr,
  addressToFr,
  deriveSharedSecret,
  NotePlaintext,
  DarkAccount,
  KeyRepository,
} from "@hisoka/wallets";
import {
  proveDeposit,
  proveGasPayment,
  proveSplit,
} from "@hisoka/prover";

// ============================================================================
// Configuration
// ============================================================================

const SEED = process.env["SEED"] || "https://api.hisoka.io/seed";
const PRIVATE_KEY = process.env["PRIVATE_KEY"] ||
  "3e8a4387dce9ecce4d3dabf84e8d3883074a4756ae369906175e8ca40f52af68";
const ARB_RPC = "https://sepolia-rollup.arbitrum.io/rpc";

// Live contracts (Arbitrum Sepolia, 2026-04-03)
const DARKPOOL = "0x7A3B2A44559A4b66cCA2E207cd8aDE5b23BE6b7B";
const TOKEN = "0x208be235AAB9b8b5d86285b2684c8e6743e662b5";
const MULTICALL = "0xe626Cfc690408Cc6d4b5eE202dDE1C411223e6AE";

const COMPLIANCE_PK: [bigint, bigint] = [
  2909031008386358327132354277111216880256503916539392122560170136801583909797n,
  846402003506115650658453623435352858314482596961745278718792737089180331275n,
];

const BN254_FR_MODULUS =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

const DARKPOOL_ABI = [
  "function deposit(bytes proof, bytes32[] publicInputs)",
  "function split(bytes proof, bytes32[] publicInputs)",
  "function payRelayer(bytes proof, bytes32[] publicInputs)",
  "function getCurrentRoot() view returns (bytes32)",
  "function getMerklePath(uint256 leafIndex) view returns (bytes32[32])",
  "event NewNote(uint256 indexed leafIndex, bytes32 indexed commitment, uint256 ephemeralPK_x, uint256 ephemeralPK_y, bytes32[7] packedCiphertext)",
];

const MULTICALL_ABI = [
  "function multicall((address target, bytes data, uint256 value, bool requireSuccess)[] calls)",
];

const ERC20_ABI = [
  "function approve(address,uint256) returns (bool)",
  "function balanceOf(address) view returns (uint256)",
  "function mint(address,uint256)",
];

const log = (msg: string) =>
  console.log(`[${new Date().toISOString().slice(11, 23)}] ${msg}`);

// ============================================================================
// Helpers
// ============================================================================

interface DepositedNote {
  note: NotePlaintext;
  ephemeralSk: Fr;
  leafIndex: number;
  commitment: string;
}

async function broadcastViaMixnet(
  client: NoxClient,
  signer: ethers.Wallet,
  provider: ethers.JsonRpcProvider,
  to: string,
  data: string,
  gasLimit: bigint,
): Promise<ethers.TransactionReceipt> {
  const nonce = await provider.getTransactionCount(signer.address);
  const feeData = await provider.getFeeData();
  const signedTx = await signer.signTransaction({
    to,
    data,
    value: 0n,
    nonce,
    chainId: 421614n,
    gasLimit,
    maxFeePerGas: feeData.maxFeePerGas ?? 1000000000n,
    maxPriorityFeePerGas: feeData.maxPriorityFeePerGas ?? 100000000n,
    type: 2,
  });
  const resp = await client.broadcastSignedTransaction(ethers.getBytes(signedTx));
  const txHash = "0x" + Array.from(resp.slice(0, 32)).map((b) => b.toString(16).padStart(2, "0")).join("");
  log(`  TX: ${txHash}`);
  const receipt = await provider.waitForTransaction(txHash, 1, 60_000);
  if (!receipt || receipt.status !== 1) throw new Error(`TX reverted: ${txHash}`);
  log(`  Confirmed: block=${receipt.blockNumber}, gas=${receipt.gasUsed}`);
  return receipt;
}

function parseNewNoteEvent(receipt: ethers.TransactionReceipt): { leafIndex: number; commitment: string } {
  const iface = new ethers.Interface(DARKPOOL_ABI);
  for (const eventLog of receipt.logs) {
    try {
      const parsed = iface.parseLog({ topics: eventLog.topics as string[], data: eventLog.data });
      if (parsed && parsed.name === "NewNote") {
        return {
          leafIndex: Number(parsed.args[0]),
          commitment: parsed.args[1],
        };
      }
    } catch {
      continue;
    }
  }
  throw new Error("NewNote event not found in receipt");
}

// ============================================================================
// Main
// ============================================================================

async function main() {
  log("╔═══════════════════════════════════════════════════════╗");
  log("║  LIVE ZK TRAFFIC GENERATOR -- Real Noir Proofs       ║");
  log("╚═══════════════════════════════════════════════════════╝\n");

  const provider = new ethers.JsonRpcProvider(ARB_RPC);
  const signer = new ethers.Wallet(PRIVATE_KEY, provider);
  log(`Wallet: ${signer.address}`);

  const balance = await provider.getBalance(signer.address);
  log(`ETH: ${ethers.formatEther(balance)}`);

  // Connect to mixnet
  log("\nConnecting to NOX mixnet...");
  const client = await NoxClient.connect({
    seeds: [SEED + "/topology"],
    timeoutMs: 60_000,
    surbsPerRequest: 10,
    powDifficulty: 3,
    dangerouslySkipFingerprintCheck: true,
  });
  log("Connected to mixnet!");

  // Ensure token balance
  const token = new ethers.Contract(TOKEN, ERC20_ABI, signer);
  let tokenBal = await token.balanceOf(signer.address);
  if (tokenBal < ethers.parseEther("1000")) {
    log("Minting NOX-STK...");
    await (await token.mint(signer.address, ethers.parseEther("100000"))).wait();
    tokenBal = await token.balanceOf(signer.address);
  }
  log(`NOX-STK: ${ethers.formatEther(tokenBal)}`);

  // Approve DarkPool
  await (await token.approve(DARKPOOL, ethers.MaxUint256)).wait();
  log("DarkPool approved for token spending");

  // Create dark account from signature
  const sig = await signer.signMessage("hisoka.darkpool.account.v1");
  const account = await DarkAccount.fromSignature(sig);
  const keyRepo = new KeyRepository(account, COMPLIANCE_PK);
  const darkPool = new ethers.Contract(DARKPOOL, DARKPOOL_ABI, provider);

  // ========================================================================
  // PHASE 1: Deposits (user signs, broadcasts via mixnet)
  // ========================================================================

  log("\n╔═══════════════════════════════════════════════════════╗");
  log("║  PHASE 1: DEPOSITS (broadcast via mixnet)            ║");
  log("╚═══════════════════════════════════════════════════════╝\n");

  const iface = new ethers.Interface(DARKPOOL_ABI);
  const depositedNotes: DepositedNote[] = [];

  // Deposit 1: Action fund (100 tokens)
  {
    log("Deposit 1: 100 NOX-STK (action fund)...");
    const { sk: ephSk } = await keyRepo.nextEphemeralParams();
    const note: NotePlaintext = {
      asset_id: addressToFr(TOKEN),
      value: toFr(ethers.parseEther("100")),
      secret: toFr(BigInt(ethers.hexlify(ethers.randomBytes(31)))),
      nullifier: toFr(BigInt(ethers.hexlify(ethers.randomBytes(31)))),
      timelock: toFr(0n),
      hashlock: toFr(0n),
    };

    log("  Generating deposit proof...");
    const t0 = Date.now();
    const proof = await proveDeposit({
      notePlaintext: note,
      ephemeralSk: ephSk,
      compliancePk: COMPLIANCE_PK,
    });
    log(`  Proof generated in ${Date.now() - t0}ms`);

    const calldata = iface.encodeFunctionData("deposit", [
      ethers.hexlify(proof.proof),
      proof.publicInputs.map((v: string) => ethers.zeroPadValue(v, 32)),
    ]);

    const receipt = await broadcastViaMixnet(client, signer, provider, DARKPOOL, calldata, 15000000n);
    const { leafIndex, commitment } = parseNewNoteEvent(receipt);
    log(`  Leaf: ${leafIndex}, Commitment: ${commitment.slice(0, 18)}...`);

    depositedNotes.push({ note, ephemeralSk: ephSk, leafIndex, commitment });
  }

  // Deposit 2: Gas fund (10 tokens)
  {
    log("\nDeposit 2: 10 NOX-STK (gas fund)...");
    const { sk: ephSk } = await keyRepo.nextEphemeralParams();
    const note: NotePlaintext = {
      asset_id: addressToFr(TOKEN),
      value: toFr(ethers.parseEther("10")),
      secret: toFr(BigInt(ethers.hexlify(ethers.randomBytes(31)))),
      nullifier: toFr(BigInt(ethers.hexlify(ethers.randomBytes(31)))),
      timelock: toFr(0n),
      hashlock: toFr(0n),
    };

    const proof = await proveDeposit({
      notePlaintext: note,
      ephemeralSk: ephSk,
      compliancePk: COMPLIANCE_PK,
    });

    const calldata = iface.encodeFunctionData("deposit", [
      ethers.hexlify(proof.proof),
      proof.publicInputs.map((v: string) => ethers.zeroPadValue(v, 32)),
    ]);

    const receipt = await broadcastViaMixnet(client, signer, provider, DARKPOOL, calldata, 15000000n);
    const { leafIndex, commitment } = parseNewNoteEvent(receipt);
    log(`  Leaf: ${leafIndex}, Commitment: ${commitment.slice(0, 18)}...`);

    depositedNotes.push({ note, ephemeralSk: ephSk, leafIndex, commitment });
  }

  log(`\nPhase 1 complete: ${depositedNotes.length} notes deposited on-chain via mixnet`);

  // ========================================================================
  // PHASE 2: Split via paid multicall (exit node submits, earns revenue)
  // ========================================================================

  log("\n╔═══════════════════════════════════════════════════════╗");
  log("║  PHASE 2: SPLIT (gas-paid via mixnet -- exit earns)  ║");
  log("╚═══════════════════════════════════════════════════════╝\n");

  const actionNote = depositedNotes[0]!;
  const gasPaymentNote = depositedNotes[1]!;

  // Get Merkle root and paths from on-chain
  const merkleRoot = await darkPool.getCurrentRoot();
  log(`Merkle root: ${merkleRoot.toString().slice(0, 18)}...`);

  const actionPath = await darkPool.getMerklePath(actionNote.leafIndex);
  const gasPath = await darkPool.getMerklePath(gasPaymentNote.leafIndex);
  log(`Action note path: leaf=${actionNote.leafIndex}`);
  log(`Gas note path: leaf=${gasPaymentNote.leafIndex}`);

  // Derive shared secrets for note spending
  const actionSecret = await deriveSharedSecret(actionNote.ephemeralSk, COMPLIANCE_PK);
  const gasSecret = await deriveSharedSecret(gasPaymentNote.ephemeralSk, COMPLIANCE_PK);

  // Build split proof: 100 -> 60 + 40
  log("\nBuilding split proof (100 -> 60 + 40)...");
  const { sk: sk1 } = await keyRepo.nextEphemeralParams();
  const { sk: sk2 } = await keyRepo.nextEphemeralParams();

  const noteOut1: NotePlaintext = {
    asset_id: actionNote.note.asset_id,
    value: toFr(ethers.parseEther("60")),
    secret: toFr(BigInt(ethers.hexlify(ethers.randomBytes(31)))),
    nullifier: toFr(BigInt(ethers.hexlify(ethers.randomBytes(31)))),
    timelock: toFr(0n),
    hashlock: toFr(0n),
  };
  const noteOut2: NotePlaintext = {
    asset_id: actionNote.note.asset_id,
    value: toFr(ethers.parseEther("40")),
    secret: toFr(BigInt(ethers.hexlify(ethers.randomBytes(31)))),
    nullifier: toFr(BigInt(ethers.hexlify(ethers.randomBytes(31)))),
    timelock: toFr(0n),
    hashlock: toFr(0n),
  };

  const t1 = Date.now();
  const splitProof = await proveSplit({
    merkleRoot: toFr(BigInt(merkleRoot)),
    currentTimestamp: Math.floor(Date.now() / 1000),
    compliancePk: COMPLIANCE_PK,
    noteIn: actionNote.note,
    secretIn: actionSecret,
    indexIn: actionNote.leafIndex,
    pathIn: actionPath.map((p: string) => toFr(BigInt(p))),
    preimageIn: toFr(0),
    noteOut1,
    skOut1: sk1,
    noteOut2,
    skOut2: sk2,
  });
  log(`Split proof generated in ${Date.now() - t1}ms`);

  // Build gas payment proof
  const splitCalldata = iface.encodeFunctionData("split", [
    ethers.hexlify(splitProof.proof),
    splitProof.publicInputs.map((v: string) => ethers.zeroPadValue(v, 32)),
  ]);
  const executionHash = toFr(BigInt(ethers.keccak256(splitCalldata)) % BN254_FR_MODULUS);

  const gasPaymentFee = ethers.parseEther("1"); // 1 token fee
  const gasChangeValue = gasPaymentNote.note.value.toBigInt() - gasPaymentFee;
  const { sk: changeEphSk } = await keyRepo.nextEphemeralParams();
  const gasChangeNote: NotePlaintext = {
    asset_id: gasPaymentNote.note.asset_id,
    value: toFr(gasChangeValue),
    secret: toFr(BigInt(ethers.hexlify(ethers.randomBytes(31)))),
    nullifier: toFr(BigInt(ethers.hexlify(ethers.randomBytes(31)))),
    timelock: toFr(0n),
    hashlock: toFr(0n),
  };

  // Pick a random exit node as relayer address
  const topology = await fetch(SEED + "/topology").then((r) => r.json());
  const exitNodes = topology.nodes.filter((n: any) => n.role === 2);
  const relayer = exitNodes[Math.floor(Math.random() * exitNodes.length)];
  log(`Relayer (exit node): ${relayer.address.slice(0, 14)}...`);

  log("Building gas payment proof...");
  const t2 = Date.now();
  const gasProof = await proveGasPayment({
    merkleRoot: toFr(BigInt(merkleRoot)),
    currentTimestamp: Math.floor(Date.now() / 1000),
    paymentValue: toFr(gasPaymentFee),
    paymentAssetId: addressToFr(TOKEN),
    relayerAddress: addressToFr(relayer.address),
    executionHash,
    compliancePk: COMPLIANCE_PK,
    oldNote: gasPaymentNote.note,
    oldSharedSecret: gasSecret,
    oldNoteIndex: gasPaymentNote.leafIndex,
    oldNotePath: gasPath.map((p: string) => toFr(BigInt(p))),
    hashlockPreimage: toFr(0),
    changeNote: gasChangeNote,
    changeEphemeralSk: changeEphSk,
  });
  log(`Gas payment proof generated in ${Date.now() - t2}ms`);

  // Encode multicall: [payRelayer, split]
  const payRelayerCalldata = iface.encodeFunctionData("payRelayer", [
    ethers.hexlify(gasProof.proof),
    gasProof.publicInputs.map((v: string) => ethers.zeroPadValue(v, 32)),
  ]);

  const multicallIface = new ethers.Interface(MULTICALL_ABI);
  const multicallCalldata = multicallIface.encodeFunctionData("multicall", [
    [
      { target: DARKPOOL, data: payRelayerCalldata, value: 0n, requireSuccess: true },
      { target: DARKPOOL, data: splitCalldata, value: 0n, requireSuccess: true },
    ],
  ]);

  // Submit via mixnet -- exit node executes, earns the gas payment
  log("\nSubmitting paid multicall via mixnet (exit node earns gas payment)...");
  const t3 = Date.now();
  const resp = await client.submitTransaction(MULTICALL, ethers.getBytes(multicallCalldata));
  const text = new TextDecoder().decode(resp);
  if (text.startsWith("tx_error:")) {
    throw new Error(`Multicall failed: ${text}`);
  }
  const txHash = "0x" + Array.from(resp.slice(0, 32)).map((b) => b.toString(16).padStart(2, "0")).join("");
  log(`Multicall TX: ${txHash} (${Date.now() - t3}ms via mixnet)`);

  const receipt = await provider.waitForTransaction(txHash, 1, 60_000);
  if (!receipt || receipt.status !== 1) {
    throw new Error(`Multicall TX reverted: ${txHash}`);
  }
  log(`Confirmed! Block: ${receipt.blockNumber}, Gas: ${receipt.gasUsed}`);
  log(`Exit node earned gas payment of ${ethers.formatEther(gasPaymentFee)} NOX-STK`);

  // ========================================================================
  // Summary
  // ========================================================================

  log("\n╔═══════════════════════════════════════════════════════╗");
  log("║  SUMMARY                                             ║");
  log("╚═══════════════════════════════════════════════════════╝");
  log(`  Deposits:     2 (broadcast via mixnet with real ZK proofs)`);
  log(`  Splits:       1 (gas-paid via exit node with real ZK proofs)`);
  log(`  Gas payment:  ${ethers.formatEther(gasPaymentFee)} NOX-STK to exit node`);
  log(`  TX:           ${txHash}`);
  log(`  Exit node revenue is now visible on map.hisoka.io`);

  client.disconnect();
  log("\nDone!");
}

main().catch((e) => {
  console.error("Fatal:", e);
  process.exit(1);
});
