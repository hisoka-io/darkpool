// Pays for one Howl action with a private fee note through a Nox exit, using `executePaid` from nox-client.
//
//   LIVE_PAID_MODE=<mode> NOX_SDK_DIR=<built nox-sdk checkout> DEPLOYMENT_RECORD_PATH=<deployment.json> \
//     NODE_OPTIONS="--import tsx" pnpm exec hardhat run test/nox/live_paid_execution.ts --network arbitrumSepolia
//
// Modes:
//   deposit  shield DEPOSIT_AMOUNTS (comma separated, fee-asset units) as one note each and list the notes
//   dry-run  quote, prove the fee and simulate a paid withdraw; nothing is submitted
//   single   paid `DarkPool.withdraw` of WITHDRAW_AMOUNT to WITHDRAW_RECIPIENT
//   bundle   paid `BundleExecutor.execute`: one withdraw, then a transfer of BUNDLE_AMOUNTS[i] to
//            BUNDLE_RECIPIENTS[i] for every i
//
// The paid modes need FEE_NOTE_NULLIFIER, ACTION_NOTE_NULLIFIER (both printed by every run), MAX_TOTAL_FEE
// (fee-asset units) and EVIDENCE_PATH. RESUME_EVIDENCE_PATH names the evidence file of an earlier run of
// the same mode whose result was `unknown`: the same action and intent are resumed and nothing new is proven.
//
// On the `arbitrumSepoliaFork` network (an anvil fork) the exit is a throwaway local key that signs its own
// quote and sends `execute` itself, so the deployed contracts are rehearsed with the same gas limits and no
// mixnet. On every other network the request goes through the mixnet to a registered paid exit.

import { ethers, network } from "hardhat";
import type {
  Filter,
  FilterByBlockHash,
  Interface,
  Log,
  TransactionReceipt,
} from "ethers";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import {
  buildBundle,
  bundleActionGasLimit,
  encodeBundleExecute,
  HOWL_PAYMENT_GAS_LIMIT,
  HOWL_WITHDRAW_ACTION_GAS_LIMIT,
  howlPaymentSource,
  type BundleCall,
  type HowlPaymentSource,
} from "@hisoka/adaptors";
import { toFr } from "@hisoka/wallets";
import { TestWallet } from "../helpers/TestWallet";

const FORK_NETWORK = "arbitrumSepoliaFork";
const MODES = ["deposit", "dry-run", "single", "bundle"] as const;
type Mode = (typeof MODES)[number];

const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";
const BASIS_POINTS = 10_000n;
/** Blocks per `eth_getLogs` request while the wallet scans the pool. */
const DEFAULT_LOG_RANGE_BLOCKS = 1_000_000;
/** Seconds a bundle stays executable after it is built. */
const BUNDLE_DEADLINE_SECS = 600n;
/** Gas each bundled ERC-20 transfer may use; a transfer to a new holder stays near half of it. */
const BUNDLE_TRANSFER_GAS_LIMIT = 100_000n;
const BUNDLE_RETURN_DATA_LIMIT = 32n;
/** A standalone withdraw proof carries a non-zero intent so the wallet proves it and submits nothing. */
const PROOF_ONLY_INTENT = 1n;
/** The buffer a fleet exit adds to its own gas estimate (`gas_limit_buffer_bps`). */
const EXIT_GAS_BUFFER_BPS = 2_000n;
/** Quote lifetime, fees and funding of the local exit of a fork rehearsal. */
const FORK_QUOTE_TTL_SECS = 30n;
const FORK_EXIT_FEE = "0.5";
const FORK_NETWORK_FEE = "0.025";
const FORK_EXIT_BALANCE = "0x56bc75e2d63100000";
const FORK_FEE_PER_GAS_MULTIPLIER = 2n;

interface DeploymentRecord {
  readonly chainId: number;
  readonly startBlock: number;
  readonly compliance: readonly [bigint, bigint];
  readonly darkPool: string;
  readonly noxRegistry: string;
  readonly noxRewardPool: string;
  readonly noxEntryPoint: string;
  readonly howlPaymentAdapter: string;
  readonly stakingToken: string;
  readonly bundleExecutor: string;
}

interface PaidTopologyNode {
  readonly id: string;
  readonly address: string;
  readonly routingAddress: string;
  readonly publicKey: Uint8Array;
  readonly layer: number;
  readonly role: number;
}

interface PaidQuoteRequest {
  readonly chainId: bigint;
  readonly entryPoint: Uint8Array;
  readonly clientIntentId: Uint8Array;
  readonly paymentAdapter: Uint8Array;
  readonly paymentId: Uint8Array;
  readonly feeAsset: Uint8Array;
  readonly paymentGasLimit: bigint;
  readonly actionTarget: Uint8Array;
  readonly actionCalldataHash: Uint8Array;
  readonly actionGasLimit: bigint;
  readonly trackedAssetsHash: Uint8Array;
  readonly maximumTransactionGas: bigint;
  readonly returnDataLimit: number;
  readonly validUntilUnix: bigint;
}

interface ExecutionQuote {
  readonly quoteVersion: number;
  readonly chainId: Uint8Array;
  readonly entryPoint: Uint8Array;
  readonly exitAddress: Uint8Array;
  readonly clientIntentId: Uint8Array;
  readonly paymentAdapter: Uint8Array;
  readonly paymentId: Uint8Array;
  readonly feeAsset: Uint8Array;
  readonly exitFee: Uint8Array;
  readonly networkFee: Uint8Array;
  readonly paymentGasLimit: Uint8Array;
  readonly actionTarget: Uint8Array;
  readonly actionCalldataHash: Uint8Array;
  readonly actionGasLimit: Uint8Array;
  readonly trackedAssetsHash: Uint8Array;
  readonly maximumTransactionGas: Uint8Array;
  readonly maximumFeePerGas: Uint8Array;
  readonly returnDataLimit: Uint8Array;
  readonly validAfterUnix: bigint;
  readonly validUntilUnix: bigint;
  readonly quoteNonce: Uint8Array;
}

interface IssuedQuote {
  readonly status: "issued";
  readonly quote: ExecutionQuote;
  readonly executionId: Uint8Array;
  readonly exitSignature: Uint8Array;
  readonly selectedExit: PaidTopologyNode;
}

interface Rejection {
  readonly status: "rejected";
  readonly code: string;
  readonly retryable: boolean;
  readonly detail: string;
}

type QuoteResult = IssuedQuote | Rejection;

type SubmitOutcome =
  | {
      readonly status: "submitted";
      readonly executionId: Uint8Array;
      readonly transactionHash: Uint8Array;
    }
  | (Rejection & { readonly executionId: Uint8Array | null });

interface PaidClient {
  selectPaidExit(options?: {
    readonly exclude?: readonly string[];
  }): PaidTopologyNode;
  requestPaidQuote(
    request: PaidQuoteRequest,
    selectedExit: PaidTopologyNode,
  ): Promise<QuoteResult>;
  submitPaidTransaction(
    issued: IssuedQuote,
    calldata: Uint8Array,
  ): Promise<SubmitOutcome>;
  rpcCall(method: string, params: unknown): Promise<unknown>;
}

type RpcSend = (method: string, params: unknown[]) => Promise<unknown>;

interface ChainReader {
  call(tx: object, block: bigint | "latest"): Promise<string>;
  estimateGas(tx: object): Promise<bigint>;
}

type PaidResult =
  | {
      readonly status: "settled" | "paid-action-failed";
      readonly executionId: string;
      readonly exit: string;
      readonly exitFee: bigint;
      readonly networkFee: bigint;
      readonly transactionHash: string;
      readonly blockNumber: bigint;
      readonly timings: Readonly<Record<string, number>>;
    }
  | {
      readonly status: "dry-run";
      readonly executionId: string;
      readonly exit: string;
      readonly exitFee: bigint;
      readonly networkFee: bigint;
      readonly maximumTransactionGas: bigint;
      readonly estimatedGas: bigint;
      readonly timings: Readonly<Record<string, number>>;
    }
  | {
      readonly status: "not-paid";
      readonly stage: string;
      readonly code: string;
      readonly detail: string;
    }
  | {
      readonly status: "unknown";
      readonly executionId: string | null;
      readonly validUntilUnix: bigint | null;
      readonly detail: string;
    };

interface PaidSdk {
  readonly NoxClient: {
    connect(config: {
      readonly ethRpcUrl: string;
      readonly registryAddress: string;
    }): Promise<PaidClient & { disconnect(): void }>;
  };
  rpcChainReader(send: RpcSend): ChainReader;
  deriveClientIntentId(
    chainId: bigint,
    entryPoint: string,
    target: string,
    data: Uint8Array,
    salt: Uint8Array,
  ): Uint8Array;
  executePaid(
    client: PaidClient,
    options: {
      readonly chainId: bigint;
      readonly entryPoint: string;
      readonly action: {
        readonly target: string;
        readonly data: Uint8Array;
        readonly gasLimit: bigint;
      };
      readonly payment: HowlPaymentSource;
      readonly maxTotalFee: bigint;
      readonly intentSalt: Uint8Array;
      readonly preflight: ChainReader;
      readonly chain?: ChainReader & {
        dataFeeGas(tx: object): Promise<bigint>;
      };
      readonly pending?: {
        readonly executionId: string;
        readonly validUntilUnix: bigint;
      };
      readonly dryRun: boolean;
    },
  ): Promise<PaidResult>;
}

interface PaidActionPlan {
  readonly target: string;
  readonly data: string;
  readonly gasLimit: bigint;
  readonly intentSalt: string;
  readonly pending?: {
    readonly executionId: string;
    readonly validUntilUnix: bigint;
  };
}

interface CallFrame {
  readonly from: string;
  readonly to: string;
  readonly gasUsed: bigint;
  readonly calls: readonly CallFrame[];
}

/** Splits a log query into bounded block ranges; RPC endpoints cap the range of one `eth_getLogs`. */
class RangedLogProvider extends ethers.JsonRpcProvider {
  constructor(
    url: string,
    chainId: number,
    private readonly rangeBlocks: number,
  ) {
    super(url, chainId, { staticNetwork: true });
  }

  override async getLogs(filter: Filter | FilterByBlockHash): Promise<Log[]> {
    const { fromBlock, toBlock } = filter as Filter;
    if ("blockHash" in filter || typeof fromBlock !== "number") {
      return super.getLogs(filter);
    }
    const head =
      typeof toBlock === "number" ? toBlock : await this.getBlockNumber();
    const logs: Log[] = [];
    for (let from = fromBlock; from <= head; from += this.rangeBlocks) {
      logs.push(
        ...(await super.getLogs({
          ...filter,
          fromBlock: from,
          toBlock: Math.min(from + this.rangeBlocks - 1, head),
        })),
      );
    }
    return logs;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function requiredEnv(name: string): string {
  const value = process.env[name];
  if (value === undefined || value === "") {
    throw new Error(`${name} is required`);
  }
  return value;
}

function recordString(record: unknown, key: string, context: string): string {
  if (!isRecord(record) || typeof record[key] !== "string" || !record[key]) {
    throw new Error(`${context}.${key} must be a non-empty string`);
  }
  return record[key];
}

function recordInteger(record: unknown, key: string, context: string): number {
  if (!isRecord(record) || !Number.isSafeInteger(record[key])) {
    throw new Error(`${context}.${key} must be a safe integer`);
  }
  return record[key] as number;
}

function parseDeployment(path: string): DeploymentRecord {
  const decoded: unknown = JSON.parse(readFileSync(path, "utf8"));
  if (!isRecord(decoded)) throw new Error("deployment record is not an object");
  const { meta, compliance, contracts } = decoded;
  const address = (key: string) =>
    ethers.getAddress(recordString(contracts, key, "contracts"));
  return {
    chainId: recordInteger(meta, "chainId", "meta"),
    startBlock: recordInteger(meta, "startBlock", "meta"),
    compliance: [
      BigInt(recordString(compliance, "publicKeyX", "compliance")),
      BigInt(recordString(compliance, "publicKeyY", "compliance")),
    ],
    darkPool: address("darkPool"),
    noxRegistry: address("noxRegistry"),
    noxRewardPool: address("noxRewardPool"),
    noxEntryPoint: address("noxEntryPoint"),
    howlPaymentAdapter: address("howlPaymentAdapter"),
    stakingToken: address("stakingToken"),
    bundleExecutor: address("bundleExecutor"),
  };
}

async function loadPaidSdk(sdkRoot: string): Promise<PaidSdk> {
  const moduleUrl = pathToFileURL(
    resolve(sdkRoot, "packages/nox-client/dist/index.js"),
  ).href;
  const loaded: unknown = await import(moduleUrl);
  if (!isRecord(loaded)) {
    throw new Error(`Nox SDK at ${moduleUrl} did not load as a module`);
  }
  for (const name of [
    "NoxClient",
    "rpcChainReader",
    "deriveClientIntentId",
    "executePaid",
  ]) {
    if (typeof loaded[name] !== "function") {
      throw new Error(`Nox SDK at ${moduleUrl} does not export ${name}`);
    }
  }
  return loaded as unknown as PaidSdk;
}

function word(value: bigint): Uint8Array {
  return ethers.getBytes(ethers.toBeHex(value, 32));
}

function fromWord(value: Uint8Array): bigint {
  return BigInt(ethers.hexlify(value));
}

function quoteStruct(quote: ExecutionQuote) {
  return {
    quoteVersion: quote.quoteVersion,
    chainId: fromWord(quote.chainId),
    entryPoint: ethers.getAddress(ethers.hexlify(quote.entryPoint)),
    exitAddress: ethers.getAddress(ethers.hexlify(quote.exitAddress)),
    clientIntentId: ethers.hexlify(quote.clientIntentId),
    paymentAdapter: ethers.getAddress(ethers.hexlify(quote.paymentAdapter)),
    paymentId: ethers.hexlify(quote.paymentId),
    feeAsset: ethers.getAddress(ethers.hexlify(quote.feeAsset)),
    exitFee: fromWord(quote.exitFee),
    networkFee: fromWord(quote.networkFee),
    paymentGasLimit: fromWord(quote.paymentGasLimit),
    actionTarget: ethers.getAddress(ethers.hexlify(quote.actionTarget)),
    actionCalldataHash: ethers.hexlify(quote.actionCalldataHash),
    actionGasLimit: fromWord(quote.actionGasLimit),
    trackedAssetsHash: ethers.hexlify(quote.trackedAssetsHash),
    maximumTransactionGas: fromWord(quote.maximumTransactionGas),
    maximumFeePerGas: fromWord(quote.maximumFeePerGas),
    returnDataLimit: fromWord(quote.returnDataLimit),
    validAfterUnix: quote.validAfterUnix,
    validUntilUnix: quote.validUntilUnix,
    quoteNonce: fromWord(quote.quoteNonce),
  };
}

function buffered(gas: bigint): bigint {
  return (
    (gas * (BASIS_POINTS + EXIT_GAS_BUFFER_BPS) + BASIS_POINTS - 1n) /
    BASIS_POINTS
  );
}

function jsonText(value: unknown): string {
  return JSON.stringify(
    value,
    (_key, item: unknown) =>
      typeof item === "bigint"
        ? item.toString()
        : item instanceof Uint8Array
          ? ethers.hexlify(item)
          : item,
    2,
  );
}

function parseFrame(value: unknown): CallFrame {
  if (!isRecord(value)) throw new Error("call trace frame is not an object");
  const calls = Array.isArray(value["calls"]) ? value["calls"] : [];
  return {
    from: ethers.getAddress(recordString(value, "from", "frame")),
    to: ethers.getAddress(recordString(value, "to", "frame")),
    gasUsed: BigInt(recordString(value, "gasUsed", "frame")),
    calls: calls.map(parseFrame),
  };
}

function frameGas(root: CallFrame, from: string, to: string): bigint | null {
  const pending = [root];
  for (let frame = pending.pop(); frame; frame = pending.pop()) {
    if (frame.from === from && frame.to === to) return frame.gasUsed;
    pending.push(...frame.calls);
  }
  return null;
}

/**
 * The exit of a fork rehearsal: signs its own quote the way a fleet exit does and sends `execute` itself.
 * The EntryPoint accepts any signer as the exit, so the deployed bytecode runs unchanged.
 */
async function forkExitClient(
  entryPointAddress: string,
  exitFee: bigint,
  networkFee: bigint,
): Promise<PaidClient> {
  const send: RpcSend = (method, params) =>
    ethers.provider.send(method, params);
  const clientVersion = await send("web3_clientVersion", []);
  if (typeof clientVersion !== "string" || !clientVersion.startsWith("anvil")) {
    throw new Error(
      `${FORK_NETWORK} must be an anvil fork, the node reports ${String(clientVersion)}`,
    );
  }
  const exit = ethers.Wallet.createRandom().connect(ethers.provider);
  await send("anvil_setBalance", [exit.address, FORK_EXIT_BALANCE]);
  const entryPoint = await ethers.getContractAt(
    "NoxEntryPoint",
    entryPointAddress,
  );
  const node: PaidTopologyNode = {
    id: exit.address,
    address: exit.address,
    routingAddress: "fork-exit",
    publicKey: new Uint8Array(32),
    layer: 0,
    role: 2,
  };
  return {
    selectPaidExit(options) {
      const excluded = (options?.exclude ?? []).map((id) => id.toLowerCase());
      if (excluded.includes(exit.address.toLowerCase())) {
        throw new Error("the fork has one exit and it is excluded");
      }
      return node;
    },
    async requestPaidQuote(request) {
      // A fleet exit stamps validAfter with the latest block time; keep the fork head at the local clock.
      const head = await ethers.provider.getBlock("latest");
      const localNow = Math.floor(Date.now() / 1000);
      if (head !== null && head.timestamp < localNow) {
        await send("evm_setNextBlockTimestamp", [localNow]);
      }
      await send("evm_mine", []);
      const latest = await ethers.provider.getBlock("latest");
      const gasPrice = (await ethers.provider.getFeeData()).gasPrice;
      if (latest === null || gasPrice === null) {
        throw new Error("fork node returned no latest block or gas price");
      }
      const validAfterUnix = BigInt(latest.timestamp);
      const ownValidUntil = validAfterUnix + FORK_QUOTE_TTL_SECS;
      const quote: ExecutionQuote = {
        quoteVersion: 1,
        chainId: word(request.chainId),
        entryPoint: request.entryPoint,
        exitAddress: ethers.getBytes(exit.address),
        clientIntentId: request.clientIntentId,
        paymentAdapter: request.paymentAdapter,
        paymentId: request.paymentId,
        feeAsset: request.feeAsset,
        exitFee: word(exitFee),
        networkFee: word(networkFee),
        paymentGasLimit: word(request.paymentGasLimit),
        actionTarget: request.actionTarget,
        actionCalldataHash: request.actionCalldataHash,
        actionGasLimit: word(request.actionGasLimit),
        trackedAssetsHash: request.trackedAssetsHash,
        maximumTransactionGas: word(request.maximumTransactionGas),
        maximumFeePerGas: word(gasPrice * FORK_FEE_PER_GAS_MULTIPLIER),
        returnDataLimit: word(BigInt(request.returnDataLimit)),
        validAfterUnix,
        validUntilUnix:
          request.validUntilUnix < ownValidUntil
            ? request.validUntilUnix
            : ownValidUntil,
        quoteNonce: ethers.randomBytes(32),
      };
      const executionId = await entryPoint.executionId(quoteStruct(quote));
      return {
        status: "issued",
        quote,
        executionId: ethers.getBytes(executionId),
        exitSignature: ethers.getBytes(
          exit.signingKey.sign(executionId).serialized,
        ),
        selectedExit: node,
      };
    },
    async submitPaidTransaction(issued, calldata) {
      const cap = fromWord(issued.quote.maximumTransactionGas);
      const data = ethers.hexlify(calldata);
      const estimate = await ethers.provider.estimateGas({
        from: exit.address,
        to: entryPointAddress,
        data,
      });
      if (buffered(estimate) > cap) {
        return {
          status: "rejected",
          executionId: issued.executionId,
          code: "GasCapExceeded",
          retryable: false,
          detail: `estimate ${estimate} with the exit buffer exceeds the signed cap ${cap}`,
        };
      }
      const transaction = await exit.sendTransaction({
        to: entryPointAddress,
        data,
        gasLimit: buffered(estimate),
      });
      return {
        status: "submitted",
        executionId: issued.executionId,
        transactionHash: ethers.getBytes(transaction.hash),
      };
    },
    rpcCall(method, params) {
      if (!Array.isArray(params)) {
        throw new Error(`${method} params must be an array`);
      }
      return send(method, params);
    },
  };
}

function loadResume(path: string, mode: Mode): PaidActionPlan {
  const decoded: unknown = JSON.parse(readFileSync(path, "utf8"));
  if (!isRecord(decoded) || decoded["mode"] !== mode) {
    throw new Error(`${path} is not the evidence of a ${mode} run`);
  }
  const action = decoded["action"];
  const result = decoded["result"];
  const plan = {
    target: recordString(action, "target", "action"),
    data: recordString(action, "data", "action"),
    gasLimit: BigInt(recordString(action, "gasLimit", "action")),
    intentSalt: recordString(decoded, "intentSalt", "evidence"),
  };
  if (
    !isRecord(result) ||
    typeof result["executionId"] !== "string" ||
    typeof result["validUntilUnix"] !== "string"
  ) {
    return plan;
  }
  return {
    ...plan,
    pending: {
      executionId: result["executionId"],
      validUntilUnix: BigInt(result["validUntilUnix"]),
    },
  };
}

async function main(): Promise<void> {
  const mode = requiredEnv("LIVE_PAID_MODE") as Mode;
  if (!MODES.includes(mode)) {
    throw new Error(`LIVE_PAID_MODE must be one of ${MODES.join(", ")}`);
  }
  const record = parseDeployment(requiredEnv("DEPLOYMENT_RECORD_PATH"));
  const chainId = (await ethers.provider.getNetwork()).chainId;
  if (chainId !== BigInt(record.chainId)) {
    throw new Error(
      `network ${network.name} has chain id ${chainId}, the deployment record is for ${record.chainId}`,
    );
  }
  const onFork = network.name === FORK_NETWORK;
  const [signer] = await ethers.getSigners();
  if (!signer) {
    throw new Error(`network ${network.name} has no signing account`);
  }
  if (!("url" in network.config)) {
    throw new Error(`network ${network.name} has no RPC URL`);
  }
  const logRange = Number(
    process.env["LOG_RANGE_BLOCKS"] ?? DEFAULT_LOG_RANGE_BLOCKS,
  );
  if (!Number.isSafeInteger(logRange) || logRange <= 0) {
    throw new Error("LOG_RANGE_BLOCKS must be a positive integer");
  }
  const scanProvider = new RangedLogProvider(
    network.config.url,
    record.chainId,
    logRange,
  );
  const send: RpcSend = (method, params) =>
    ethers.provider.send(method, params);

  const darkPool = await ethers.getContractAt("DarkPool", record.darkPool);
  const token = await ethers.getContractAt("MockERC20", record.stakingToken);
  const entryPoint = await ethers.getContractAt(
    "NoxEntryPoint",
    record.noxEntryPoint,
  );
  const rewardPool = await ethers.getContractAt(
    "NoxRewardPool",
    record.noxRewardPool,
  );
  const executor = await ethers.getContractAt(
    "BundleExecutor",
    record.bundleExecutor,
  );
  const decimals = await token.decimals();
  const units = (name: string, value: string): bigint => {
    try {
      return ethers.parseUnits(value.trim(), decimals);
    } catch {
      throw new Error(`${name} holds an invalid amount: ${value}`);
    }
  };

  const [complianceX, complianceY, complianceVersion] =
    await darkPool.complianceKey();
  if (
    complianceX !== record.compliance[0] ||
    complianceY !== record.compliance[1] ||
    complianceVersion !== 1n
  ) {
    throw new Error(
      `pool compliance key (version ${complianceVersion}) differs from the version 1 key of the deployment record`,
    );
  }

  const wallet = await TestWallet.create(
    signer,
    darkPool.connect(scanProvider),
    token,
    record.startBlock,
    [complianceX, complianceY],
  );
  const syncWallet = async (): Promise<void> => {
    await wallet.sync();
    // The ephemeral counter is in memory; continue after the highest index already used on chain.
    const state = wallet.keyRepo.getState();
    await wallet.keyRepo.restore({
      ...state,
      selfMintCounter: Math.max(
        state.selfMintCounter,
        state.highestMatchedSelf + 1,
      ),
    });
    const poolLeaves = await darkPool.getNextLeafIndex();
    if (BigInt(wallet.tree.nextLeafIndex) !== poolLeaves) {
      throw new Error(
        `wallet tree holds ${wallet.tree.nextLeafIndex} leaves, the pool holds ${poolLeaves}`,
      );
    }
  };
  const printNotes = (): void => {
    for (const note of wallet.utxoRepo.getUnspentNotes()) {
      console.log(
        `[note] leaf=${note.leafIndex} value=${ethers.formatUnits(note.note.value, decimals)}` +
          ` nullifier=${note.nullifier.toString()} commitment=${note.commitment.toString()}`,
      );
    }
  };
  const unspentNote = (name: string) => {
    const nullifier = requiredEnv(name).toLowerCase();
    const note = wallet.utxoRepo
      .getUnspentNotes()
      .find((n) => n.nullifier.toString().toLowerCase() === nullifier);
    if (!note) throw new Error(`${name} ${nullifier} is not an unspent note`);
    return note;
  };

  console.log(
    `[run] mode=${mode} network=${network.name} chainId=${chainId} wallet=${signer.address}` +
      ` backend=${onFork ? "fork-exit" : "mixnet"}`,
  );
  await syncWallet();
  printNotes();

  if (mode === "deposit") {
    const amounts = requiredEnv("DEPOSIT_AMOUNTS")
      .split(",")
      .map((value) => units("DEPOSIT_AMOUNTS", value));
    for (const amount of amounts) {
      const { commitment, receipt } = await wallet.deposit(amount);
      await syncWallet();
      console.log(
        `[deposit] value=${ethers.formatUnits(amount, decimals)} commitment=${commitment.toString()}` +
          ` tx=${receipt?.hash} block=${receipt?.blockNumber}`,
      );
    }
    printNotes();
    return;
  }

  const evidencePath = requiredEnv("EVIDENCE_PATH");
  const resumePath = process.env["RESUME_EVIDENCE_PATH"];
  if (resumePath === undefined && existsSync(evidencePath)) {
    throw new Error(
      `${evidencePath} exists; resume it with RESUME_EVIDENCE_PATH or choose a new EVIDENCE_PATH`,
    );
  }
  const maxTotalFee = units("MAX_TOTAL_FEE", requiredEnv("MAX_TOTAL_FEE"));
  const feeNote = unspentNote("FEE_NOTE_NULLIFIER");
  if (feeNote.note.value <= maxTotalFee) {
    throw new Error(
      `fee note holds ${feeNote.note.value}, it must exceed MAX_TOTAL_FEE ${maxTotalFee}`,
    );
  }

  // The action is fixed before any quote: the proof spends a note other than the fee note.
  const balanceWatch: string[] = [record.bundleExecutor];
  const spentNullifiers = [feeNote.nullifier.toString()];
  let plan: PaidActionPlan;
  if (resumePath !== undefined) {
    plan = loadResume(resumePath, mode);
  } else {
    const actionNote = unspentNote("ACTION_NOTE_NULLIFIER");
    if (actionNote.nullifier.equals(feeNote.nullifier)) {
      throw new Error("the action note and the fee note must be two notes");
    }
    spentNullifiers.push(actionNote.nullifier.toString());
    const intentSalt = ethers.hexlify(ethers.randomBytes(32));
    if (mode === "bundle") {
      const amounts = requiredEnv("BUNDLE_AMOUNTS")
        .split(",")
        .map((value) => units("BUNDLE_AMOUNTS", value));
      const recipients = requiredEnv("BUNDLE_RECIPIENTS")
        .split(",")
        .map((value) => ethers.getAddress(value.trim()));
      if (amounts.length < 2 || amounts.length !== recipients.length) {
        throw new Error(
          "BUNDLE_AMOUNTS and BUNDLE_RECIPIENTS must list the same two or more entries",
        );
      }
      const total = amounts.reduce((sum, amount) => sum + amount, 0n);
      if (actionNote.note.value <= total) {
        throw new Error(
          `bundle note holds ${actionNote.note.value}, it must exceed the bundled ${total}`,
        );
      }
      const latest = await ethers.provider.getBlock("latest");
      if (!latest) throw new Error("latest block is missing");
      const bundle = buildBundle(
        { chainId, executor: record.bundleExecutor, darkPool: record.darkPool },
        amounts.map(
          (amount, index): BundleCall => ({
            target: record.stakingToken,
            data: token.interface.encodeFunctionData("transfer", [
              recipients[index]!,
              amount,
            ]),
            value: 0n,
            requireSuccess: true,
            approveToken: ZERO_ADDRESS,
            approveAmount: 0n,
            gasLimit: BUNDLE_TRANSFER_GAS_LIMIT,
            returnDataLimit: BUNDLE_RETURN_DATA_LIMIT,
          }),
        ),
        BigInt(Math.max(latest.timestamp, Math.floor(Date.now() / 1000))) +
          BUNDLE_DEADLINE_SECS,
        [record.stakingToken],
        recipients,
      );
      const proof = await wallet.withdraw(total, {
        recipient: record.bundleExecutor,
        intentHash: bundle.intentHash,
        inputNullifier: actionNote.nullifier,
      });
      balanceWatch.push(...recipients);
      plan = {
        target: record.bundleExecutor,
        data: encodeBundleExecute(bundle, proof),
        gasLimit: bundleActionGasLimit(bundle),
        intentSalt,
      };
    } else {
      const amount = units("WITHDRAW_AMOUNT", requiredEnv("WITHDRAW_AMOUNT"));
      const recipient = ethers.getAddress(requiredEnv("WITHDRAW_RECIPIENT"));
      if (actionNote.note.value <= amount) {
        throw new Error(
          `action note holds ${actionNote.note.value}, it must exceed the withdrawn ${amount}`,
        );
      }
      const proof = await wallet.withdraw(amount, {
        recipient,
        intentHash: toFr(PROOF_ONLY_INTENT),
        inputNullifier: actionNote.nullifier,
      });
      balanceWatch.push(recipient);
      plan = {
        target: record.darkPool,
        data: darkPool.interface.encodeFunctionData("withdraw", [
          proof.proof,
          proof.publicInputs,
        ]),
        gasLimit: HOWL_WITHDRAW_ACTION_GAS_LIMIT,
        intentSalt,
      };
    }
  }

  const sdk = await loadPaidSdk(requiredEnv("NOX_SDK_DIR"));
  let disconnect = (): void => undefined;
  let client: PaidClient;
  if (onFork) {
    client = await forkExitClient(
      record.noxEntryPoint,
      units("FORK_EXIT_FEE", FORK_EXIT_FEE),
      units("FORK_NETWORK_FEE", FORK_NETWORK_FEE),
    );
  } else {
    const connected = await sdk.NoxClient.connect({
      ethRpcUrl: network.config.url,
      registryAddress: record.noxRegistry,
    });
    client = connected;
    disconnect = () => connected.disconnect();
  }

  const quotes: object[] = [];
  const submissions: object[] = [];
  const recording: PaidClient = {
    selectPaidExit: (options) => client.selectPaidExit(options),
    async requestPaidQuote(request, selectedExit) {
      const requestedAtMs = Date.now();
      const outcome = await client.requestPaidQuote(request, selectedExit);
      quotes.push({
        requestedExit: selectedExit.id,
        requestedAtMs,
        answeredAtMs: Date.now(),
        ...(outcome.status === "issued"
          ? {
              status: outcome.status,
              issuingExit: outcome.selectedExit.id,
              issuingExitRoute: outcome.selectedExit.routingAddress,
              executionId: ethers.hexlify(outcome.executionId),
              quote: quoteStruct(outcome.quote),
            }
          : outcome),
      });
      return outcome;
    },
    async submitPaidTransaction(issued, calldata) {
      const submittedAtMs = Date.now();
      const outcome = await client.submitPaidTransaction(issued, calldata);
      submissions.push({
        ...outcome,
        executionId: ethers.hexlify(issued.executionId),
        calldataBytes: calldata.length,
        submittedAtMs,
        answeredAtMs: Date.now(),
      });
      return outcome;
    },
    rpcCall: (method, params) => client.rpcCall(method, params),
  };

  const intentId = ethers.hexlify(
    sdk.deriveClientIntentId(
      chainId,
      record.noxEntryPoint,
      plan.target,
      ethers.getBytes(plan.data),
      ethers.getBytes(plan.intentSalt),
    ),
  );
  const evidence: Record<string, unknown> = {
    mode,
    network: network.name,
    backend: onFork ? "fork-exit" : "mixnet",
    chainId,
    wallet: signer.address,
    entryPoint: record.noxEntryPoint,
    feeNote: {
      nullifier: feeNote.nullifier.toString(),
      commitment: feeNote.commitment.toString(),
      leafIndex: feeNote.leafIndex,
      value: feeNote.note.value,
    },
    spentNullifiers,
    maxTotalFee,
    paymentGasLimit: HOWL_PAYMENT_GAS_LIMIT,
    intentSalt: plan.intentSalt,
    clientIntentId: intentId,
    action: { target: plan.target, data: plan.data, gasLimit: plan.gasLimit },
    quotes,
    submissions,
  };
  const save = (): void =>
    writeFileSync(evidencePath, `${jsonText(evidence)}\n`);
  save();
  console.log(
    `[spend] feeNote=${feeNote.nullifier.toString()} actionNotes=${spentNullifiers.slice(1).join(",") || "resumed"}`,
  );
  console.log(
    `[plan] target=${plan.target} actionGasLimit=${plan.gasLimit} paymentGasLimit=${HOWL_PAYMENT_GAS_LIMIT}` +
      ` actionBytes=${ethers.dataLength(plan.data)} maxTotalFee=${ethers.formatUnits(maxTotalFee, decimals)}` +
      ` clientIntentId=${intentId}`,
  );

  const balances = async (blockTag: number | "latest") =>
    Object.fromEntries(
      await Promise.all(
        balanceWatch.map(
          async (holder) =>
            [holder, await token.balanceOf(holder, { blockTag })] as const,
        ),
      ),
    );
  const direct = sdk.rpcChainReader(send);
  const startedAtMs = Date.now();
  let result: PaidResult;
  try {
    result = await sdk.executePaid(recording, {
      chainId,
      entryPoint: record.noxEntryPoint,
      action: {
        target: plan.target,
        data: ethers.getBytes(plan.data),
        gasLimit: plan.gasLimit,
      },
      payment: howlPaymentSource({
        adapter: record.howlPaymentAdapter,
        feeAsset: record.stakingToken,
        feeNoteNullifier: feeNote.nullifier.toString(),
        feeNoteValue: feeNote.note.value,
        proveFeeWithdraw: (amount, recipient, intentHash) =>
          wallet.withdraw(amount, {
            recipient,
            intentHash,
            inputNullifier: feeNote.nullifier,
          }),
      }),
      maxTotalFee,
      intentSalt: ethers.getBytes(plan.intentSalt),
      // The simulation carries the fee proof, so it goes to the RPC endpoint of this script.
      preflight: direct,
      // An anvil fork has no Arbitrum NodeInterface, so the fork run reads the chain directly.
      ...(onFork
        ? { chain: { ...direct, dataFeeGas: () => Promise.resolve(0n) } }
        : {}),
      ...(plan.pending === undefined ? {} : { pending: plan.pending }),
      dryRun: mode === "dry-run",
    });
  } finally {
    disconnect();
  }
  evidence["endToEndMs"] = Date.now() - startedAtMs;
  evidence["result"] = result;
  save();
  console.log(`[result] ${jsonText(result).replace(/\s+/g, " ")}`);

  if (result.status === "dry-run") {
    const exitGasLimit = buffered(result.estimatedGas);
    console.log(
      `[dry-run] estimate=${result.estimatedGas} exitGasLimit=${exitGasLimit} cap=${result.maximumTransactionGas}` +
        ` capSlackBps=${((result.maximumTransactionGas - exitGasLimit) * BASIS_POINTS) / result.maximumTransactionGas}` +
        ` fee=${ethers.formatUnits(result.exitFee + result.networkFee, decimals)}`,
    );
    return;
  }
  if (result.status === "not-paid" || result.status === "unknown") {
    throw new Error(
      `paid execution ended ${result.status}: ${result.detail}; evidence at ${evidencePath}`,
    );
  }

  const receipt: TransactionReceipt | null =
    await ethers.provider.getTransactionReceipt(result.transactionHash);
  if (!receipt) {
    throw new Error(`receipt of ${result.transactionHash} is missing`);
  }
  const block = await ethers.provider.getBlock(receipt.blockNumber);
  const rawReceipt = await send("eth_getTransactionReceipt", [
    result.transactionHash,
  ]);
  const before = receipt.blockNumber - 1;
  const parsed = (contract: { interface: Interface }, address: string) =>
    receipt.logs
      .filter((log) => log.address === address)
      .map((log) => contract.interface.parseLog(log))
      .flatMap((log) =>
        log === null ? [] : [{ name: log.name, args: log.args.toObject() }],
      );
  let frames: Record<string, bigint | null> | null = null;
  try {
    const trace = parseFrame(
      await send("debug_traceTransaction", [
        result.transactionHash,
        { tracer: "callTracer" },
      ]),
    );
    frames = {
      payment: frameGas(trace, record.noxEntryPoint, record.howlPaymentAdapter),
      action: frameGas(
        trace,
        await entryPoint.predictSandbox(intentId),
        ethers.getAddress(plan.target),
      ),
    };
  } catch (error: unknown) {
    console.log(
      `[trace] call trace is not served by this endpoint: ${error instanceof Error ? error.message.slice(0, 120) : String(error)}`,
    );
  }
  const gasCostWei = receipt.gasUsed * receipt.gasPrice;
  evidence["settlement"] = {
    transactionHash: receipt.hash,
    blockNumber: receipt.blockNumber,
    blockTimestamp: block?.timestamp ?? null,
    from: receipt.from,
    status: receipt.status,
    gasUsed: receipt.gasUsed,
    gasUsedForL1: isRecord(rawReceipt)
      ? (rawReceipt["gasUsedForL1"] ?? null)
      : null,
    effectiveGasPrice: receipt.gasPrice,
    gasCostWei,
    entryPointLogs: parsed(entryPoint, record.noxEntryPoint),
    darkPoolLogs: parsed(darkPool, record.darkPool).filter(
      (log) => log.name !== "NewNote",
    ),
    newNoteCommitments: receipt.logs
      .filter((log) => log.address === record.darkPool)
      .map((log) => darkPool.interface.parseLog(log))
      .flatMap((log) =>
        log?.name === "NewNote" ? [log.args["commitment"] as string] : [],
      ),
    bundleExecutorLogs: parsed(executor, record.bundleExecutor),
    exitCredit: {
      before: await rewardPool.claimableExit(result.exit, record.stakingToken, {
        blockTag: before,
      }),
      after: await rewardPool.claimableExit(result.exit, record.stakingToken, {
        blockTag: receipt.blockNumber,
      }),
    },
    networkOutstanding: {
      before: await rewardPool.networkOutstanding(record.stakingToken, {
        blockTag: before,
      }),
      after: await rewardPool.networkOutstanding(record.stakingToken, {
        blockTag: receipt.blockNumber,
      }),
    },
    balances: {
      before: await balances(before),
      after: await balances(receipt.blockNumber),
    },
    nullifiersSpent: Object.fromEntries(
      await Promise.all(
        spentNullifiers.map(
          async (nullifier) =>
            [nullifier, await darkPool.isNullifierSpent(nullifier)] as const,
        ),
      ),
    ),
    frames,
    frameLimits: {
      payment: HOWL_PAYMENT_GAS_LIMIT,
      action: plan.gasLimit,
    },
  };
  save();
  console.log(
    `[settled] status=${result.status} tx=${receipt.hash} block=${receipt.blockNumber} exit=${result.exit}` +
      ` gasUsed=${receipt.gasUsed} gasCostWei=${gasCostWei}` +
      ` fee=${ethers.formatUnits(result.exitFee + result.networkFee, decimals)}` +
      ` endToEndMs=${String(evidence["endToEndMs"])}`,
  );
  console.log(
    `[time] ${Object.entries(result.timings)
      .map(([stage, ms]) => `${stage}=${ms}ms`)
      .join(" ")}`,
  );
  if (frames !== null) {
    console.log(
      `[gas] payment=${frames["payment"]}/${HOWL_PAYMENT_GAS_LIMIT} action=${frames["action"]}/${plan.gasLimit}`,
    );
  }
  console.log(`[evidence] ${evidencePath}`);
  if (result.status !== "settled") {
    throw new Error(
      `the fee was paid and the action failed; evidence at ${evidencePath}`,
    );
  }
}

main().catch((error: unknown) => {
  console.error(error);
  process.exitCode = 1;
});
