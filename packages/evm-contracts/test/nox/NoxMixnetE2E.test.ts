import { expect } from "chai";
import { ethers } from "hardhat";
import type { Interface, JsonRpcProvider } from "ethers";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import {
  buildBundle,
  buildHowlPayment,
  bundleActionGasLimit,
  encodeBundleExecute,
  HOWL_PAYMENT_DATA_LENGTH,
  HOWL_PAYMENT_GAS_LIMIT,
  HOWL_WITHDRAW_ACTION_GAS_LIMIT,
  howlPaymentIntent,
  howlPaymentSource,
  type BundleCall,
  type HowlPaymentSource,
} from "@hisoka/adaptors";
import { Fr, toFr } from "@hisoka/wallets";
import { TestWallet } from "../helpers/TestWallet";

interface MeshNodeInfo {
  readonly id: number;
  readonly role: "relay" | "exit";
  readonly layer: number;
  readonly p2p_multiaddr: string;
  readonly ingress_url: string | null;
  readonly metrics_url: string;
  readonly sphinx_public_key: string;
  readonly peer_id: string;
  readonly db_path: string;
}

interface PaidMeshInfo {
  readonly entry_url: string;
  readonly topology_urls: readonly string[];
  readonly selected_exit: {
    readonly address: string;
    readonly node_id: number;
    readonly p2p_multiaddr: string;
    readonly metrics_url: string;
    readonly db_path: string;
  };
  readonly chain_id: number;
  readonly rpc_url: string;
  readonly entry_point_address: string;
  readonly payment_adapter_address: string;
  readonly reward_pool_address: string;
  readonly fee_asset_address: string;
  readonly native_asset_price_id: string;
  readonly fee_asset_price_id: string;
  readonly oracle_url: string;
  readonly nodes: readonly MeshNodeInfo[];
}

interface DeploymentRecord {
  readonly meta: { readonly startBlock: number };
  readonly governance: { readonly timelock: string };
  readonly contracts: {
    readonly darkPool: string;
    readonly noxRegistry: string;
    readonly noxRewardPool: string;
    readonly noxEntryPoint: string;
    readonly howlPaymentAdapter: string;
    readonly stakingToken: string;
    readonly bundleExecutor: string;
  };
}

interface PaidTopologyNode {
  readonly id: string;
  readonly address: string;
  readonly routingAddress: string;
  readonly publicKey: Uint8Array;
  readonly layer: number;
  readonly role: number;
}

interface PaidQuoteRequestV2 {
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

interface ExecutionQuoteV1 {
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

interface IssuedPaidQuoteV2 {
  readonly status: "issued";
  readonly quote: ExecutionQuoteV1;
  readonly executionId: Uint8Array;
  readonly exitSignature: Uint8Array;
  readonly selectedExit: PaidTopologyNode;
}

type PaidQuoteResultV2 =
  | IssuedPaidQuoteV2
  | {
      readonly status: "rejected";
      readonly code: string;
      readonly retryable: boolean;
      readonly detail: string;
    };

type PaidTransactionOutcomeV2 =
  | {
      readonly status: "submitted";
      readonly executionId: Uint8Array;
      readonly transactionHash: Uint8Array;
    }
  | {
      readonly status: "rejected";
      readonly executionId: Uint8Array | null;
      readonly code: string;
      readonly retryable: boolean;
      readonly detail: string;
    };

interface PaidNoxClient {
  selectPaidExit(): PaidTopologyNode;
  requestPaidQuote(
    request: PaidQuoteRequestV2,
    selectedExit: PaidTopologyNode,
  ): Promise<PaidQuoteResultV2>;
  submitPaidTransaction(
    issued: IssuedPaidQuoteV2,
    calldata: Uint8Array,
  ): Promise<PaidTransactionOutcomeV2>;
  rpcCall(method: string, params: unknown): Promise<unknown>;
  disconnect(): void;
}

interface PaidNoxClientConstructor {
  connect(config: {
    readonly seeds: readonly string[];
    readonly ethRpcUrl: string;
    readonly registryAddress: string;
    readonly powDifficulty: number;
    readonly timeoutMs: number;
    readonly surbsPerRequest: number;
  }): Promise<unknown>;
}

interface PaidChainReader {
  call(tx: object, block: bigint | "latest"): Promise<string>;
  estimateGas(tx: object): Promise<bigint>;
}

type PaidExecutionResult =
  | {
      readonly status: "settled";
      readonly executionId: string;
      readonly exit: string;
      readonly exitFee: bigint;
      readonly networkFee: bigint;
      readonly transactionHash: string;
      readonly maximumTransactionGas: bigint;
      readonly timings: Readonly<Record<string, number>>;
    }
  | {
      readonly status:
        | "paid-action-failed"
        | "dry-run"
        | "not-paid"
        | "unknown";
      readonly stage?: string;
      readonly code?: string;
      readonly detail?: string;
    };

interface PaidNoxModule {
  readonly NoxClient: PaidNoxClientConstructor;
  planPaidGas(input: {
    readonly paymentGasLimit: bigint;
    readonly actionGasLimit: bigint;
    readonly calldataGas: bigint;
  }): { readonly maximumTransactionGas: bigint };
  paidExecuteCalldata(
    actionData: Uint8Array,
    trackedAssetCount: number,
    paymentDataLength: number,
  ): { readonly gas: bigint };
  rpcChainReader(
    send: (method: string, params: unknown[]) => Promise<unknown>,
  ): PaidChainReader;
  executePaid(
    client: PaidNoxClient,
    options: {
      readonly chainId: bigint;
      readonly entryPoint: string;
      readonly action: {
        readonly target: string;
        readonly data: Uint8Array;
        readonly gasLimit?: bigint;
      };
      readonly payment: HowlPaymentSource;
      readonly maxTotalFee: bigint;
      readonly intentSalt: Uint8Array;
      readonly preflight: PaidChainReader;
    },
  ): Promise<PaidExecutionResult>;
}

const BASIS_POINTS = 10_000n;
const PAID_MESH_BUFFER_BPS = 2_000n;
const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";
const GENERIC_ACTION_GAS_LIMIT = 100_000n;
// Room each Howl gas limit keeps above a traced frame: the leaf index at inclusion is unknown when the
// limit is signed, and a withdraw costs up to one Poseidon2 hash_3 per level of the depth-32 tree.
const TREE_ALLOWANCE_GAS = 32n * 24_000n;

interface CallFrame {
  readonly type: string;
  readonly from: string;
  readonly to: string;
  readonly gasUsed: bigint;
  readonly calls: readonly CallFrame[];
}

function parseCallFrame(value: unknown, context: string): CallFrame {
  if (!isRecord(value)) throw new Error(`${context} must be an object`);
  const calls = value["calls"] ?? [];
  if (!Array.isArray(calls)) throw new Error(`${context}.calls is invalid`);
  return {
    type: requiredString(value, "type", context),
    from: ethers.getAddress(requiredString(value, "from", context)),
    to: ethers.getAddress(requiredString(value, "to", context)),
    gasUsed: BigInt(requiredString(value, "gasUsed", context)),
    calls: calls.map((call, index) =>
      parseCallFrame(call, `${context}.calls[${index}]`),
    ),
  };
}

function findFrame(root: CallFrame, from: string, to: string): CallFrame {
  const matches: CallFrame[] = [];
  const pending = [root];
  for (let frame = pending.pop(); frame; frame = pending.pop()) {
    if (frame.from === from && frame.to === to) matches.push(frame);
    pending.push(...frame.calls);
  }
  if (matches.length !== 1) {
    throw new Error(
      `expected one call frame ${from} -> ${to}, found ${matches.length}`,
    );
  }
  return matches[0]!;
}

function buffered(value: bigint): bigint {
  return (
    (value * (BASIS_POINTS + PAID_MESH_BUFFER_BPS) + BASIS_POINTS - 1n) /
    BASIS_POINTS
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function requiredString(
  record: Record<string, unknown>,
  key: string,
  context: string,
): string {
  const value = record[key];
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`${context}.${key} must be a non-empty string`);
  }
  return value;
}

function requiredNumber(
  record: Record<string, unknown>,
  key: string,
  context: string,
): number {
  const value = record[key];
  if (typeof value !== "number" || !Number.isSafeInteger(value)) {
    throw new Error(`${context}.${key} must be a safe integer`);
  }
  return value;
}

function parsePaidMesh(path: string): PaidMeshInfo {
  const decoded: unknown = JSON.parse(readFileSync(path, "utf8"));
  if (!isRecord(decoded))
    throw new Error("paid mesh manifest must be an object");
  const selectedExit = decoded["selected_exit"];
  const nodes = decoded["nodes"];
  const topologyUrls = decoded["topology_urls"];
  if (!isRecord(selectedExit))
    throw new Error("paid mesh selected_exit must be an object");
  if (!Array.isArray(nodes) || !Array.isArray(topologyUrls)) {
    throw new Error("paid mesh nodes and topology_urls must be arrays");
  }
  const parsedNodes = nodes.map((node, index): MeshNodeInfo => {
    if (!isRecord(node))
      throw new Error(`paid mesh node ${index} must be an object`);
    const role = requiredString(node, "role", `nodes[${index}]`);
    if (role !== "relay" && role !== "exit") {
      throw new Error(`nodes[${index}].role is invalid`);
    }
    const ingress = node["ingress_url"];
    if (ingress !== null && typeof ingress !== "string") {
      throw new Error(`nodes[${index}].ingress_url is invalid`);
    }
    return {
      id: requiredNumber(node, "id", `nodes[${index}]`),
      role,
      layer: requiredNumber(node, "layer", `nodes[${index}]`),
      p2p_multiaddr: requiredString(node, "p2p_multiaddr", `nodes[${index}]`),
      ingress_url: ingress,
      metrics_url: requiredString(node, "metrics_url", `nodes[${index}]`),
      sphinx_public_key: requiredString(
        node,
        "sphinx_public_key",
        `nodes[${index}]`,
      ),
      peer_id: requiredString(node, "peer_id", `nodes[${index}]`),
      db_path: requiredString(node, "db_path", `nodes[${index}]`),
    };
  });
  const parsedTopologyUrls = topologyUrls.map((url, index) => {
    if (typeof url !== "string") {
      throw new Error(`topology_urls[${index}] must be a string`);
    }
    return url;
  });
  return {
    entry_url: requiredString(decoded, "entry_url", "mesh"),
    topology_urls: parsedTopologyUrls,
    selected_exit: {
      address: requiredString(selectedExit, "address", "selected_exit"),
      node_id: requiredNumber(selectedExit, "node_id", "selected_exit"),
      p2p_multiaddr: requiredString(
        selectedExit,
        "p2p_multiaddr",
        "selected_exit",
      ),
      metrics_url: requiredString(selectedExit, "metrics_url", "selected_exit"),
      db_path: requiredString(selectedExit, "db_path", "selected_exit"),
    },
    chain_id: requiredNumber(decoded, "chain_id", "mesh"),
    rpc_url: requiredString(decoded, "rpc_url", "mesh"),
    entry_point_address: requiredString(decoded, "entry_point_address", "mesh"),
    payment_adapter_address: requiredString(
      decoded,
      "payment_adapter_address",
      "mesh",
    ),
    reward_pool_address: requiredString(decoded, "reward_pool_address", "mesh"),
    fee_asset_address: requiredString(decoded, "fee_asset_address", "mesh"),
    native_asset_price_id: requiredString(
      decoded,
      "native_asset_price_id",
      "mesh",
    ),
    fee_asset_price_id: requiredString(decoded, "fee_asset_price_id", "mesh"),
    oracle_url: requiredString(decoded, "oracle_url", "mesh"),
    nodes: parsedNodes,
  };
}

function parseDeployment(path: string): DeploymentRecord {
  const decoded: unknown = JSON.parse(readFileSync(path, "utf8"));
  if (
    !isRecord(decoded) ||
    !isRecord(decoded["meta"]) ||
    !isRecord(decoded["governance"]) ||
    !isRecord(decoded["contracts"])
  ) {
    throw new Error(
      "deployment record is missing meta, governance, or contracts",
    );
  }
  const meta = decoded["meta"];
  const governance = decoded["governance"];
  const contracts = decoded["contracts"];
  return {
    meta: { startBlock: requiredNumber(meta, "startBlock", "meta") },
    governance: {
      timelock: requiredString(governance, "timelock", "governance"),
    },
    contracts: {
      darkPool: requiredString(contracts, "darkPool", "contracts"),
      noxRegistry: requiredString(contracts, "noxRegistry", "contracts"),
      noxRewardPool: requiredString(contracts, "noxRewardPool", "contracts"),
      noxEntryPoint: requiredString(contracts, "noxEntryPoint", "contracts"),
      howlPaymentAdapter: requiredString(
        contracts,
        "howlPaymentAdapter",
        "contracts",
      ),
      stakingToken: requiredString(contracts, "stakingToken", "contracts"),
      bundleExecutor: requiredString(contracts, "bundleExecutor", "contracts"),
    },
  };
}

async function loadPaidNoxModule(sdkRoot: string): Promise<PaidNoxModule> {
  const moduleUrl = pathToFileURL(
    resolve(sdkRoot, "packages/nox-client/dist/index.js"),
  ).href;
  const loaded: unknown = await import(moduleUrl);
  if (!isRecord(loaded)) {
    throw new Error(`Nox SDK at ${moduleUrl} did not load as a module`);
  }
  for (const name of [
    "NoxClient",
    "planPaidGas",
    "paidExecuteCalldata",
    "rpcChainReader",
    "executePaid",
  ]) {
    if (typeof loaded[name] !== "function") {
      throw new Error(`Nox SDK at ${moduleUrl} does not export ${name}`);
    }
  }
  return loaded as unknown as PaidNoxModule;
}

function requirePaidMethods(client: unknown): asserts client is PaidNoxClient {
  if (!isRecord(client)) throw new Error("NoxClient instance is not an object");
  for (const method of [
    "selectPaidExit",
    "requestPaidQuote",
    "submitPaidTransaction",
    "rpcCall",
    "disconnect",
  ]) {
    if (typeof client[method] !== "function") {
      throw new Error(`NoxClient paid method is missing: ${method}`);
    }
  }
}

function baseUrl(topologyUrl: string): string {
  if (!topologyUrl.endsWith("/topology")) {
    throw new Error(`topology URL must end with /topology: ${topologyUrl}`);
  }
  return topologyUrl.slice(0, -"/topology".length);
}

function fixedBytes(hex: string, length: number, label: string): Uint8Array {
  const bytes = ethers.getBytes(hex);
  if (bytes.length !== length) {
    throw new Error(`${label} must be ${length} bytes, got ${bytes.length}`);
  }
  return bytes;
}

function word(value: Uint8Array, label: string): bigint {
  if (value.length !== 32) {
    throw new Error(`${label} must be 32 bytes, got ${value.length}`);
  }
  return BigInt(ethers.hexlify(value));
}

function quoteForContract(quote: ExecutionQuoteV1) {
  return {
    quoteVersion: quote.quoteVersion,
    chainId: word(quote.chainId, "quote.chainId"),
    entryPoint: ethers.hexlify(quote.entryPoint),
    exitAddress: ethers.hexlify(quote.exitAddress),
    clientIntentId: ethers.hexlify(quote.clientIntentId),
    paymentAdapter: ethers.hexlify(quote.paymentAdapter),
    paymentId: ethers.hexlify(quote.paymentId),
    feeAsset: ethers.hexlify(quote.feeAsset),
    exitFee: word(quote.exitFee, "quote.exitFee"),
    networkFee: word(quote.networkFee, "quote.networkFee"),
    paymentGasLimit: word(quote.paymentGasLimit, "quote.paymentGasLimit"),
    actionTarget: ethers.hexlify(quote.actionTarget),
    actionCalldataHash: ethers.hexlify(quote.actionCalldataHash),
    actionGasLimit: word(quote.actionGasLimit, "quote.actionGasLimit"),
    trackedAssetsHash: ethers.hexlify(quote.trackedAssetsHash),
    maximumTransactionGas: word(
      quote.maximumTransactionGas,
      "quote.maximumTransactionGas",
    ),
    maximumFeePerGas: word(quote.maximumFeePerGas, "quote.maximumFeePerGas"),
    returnDataLimit: word(quote.returnDataLimit, "quote.returnDataLimit"),
    validAfterUnix: quote.validAfterUnix,
    validUntilUnix: quote.validUntilUnix,
    quoteNonce: word(quote.quoteNonce, "quote.quoteNonce"),
  };
}

function revertData(error: unknown): string | null {
  if (!isRecord(error)) return null;
  if (typeof error["data"] === "string" && ethers.isHexString(error["data"])) {
    return error["data"];
  }
  for (const key of ["error", "info"] as const) {
    const nested = revertData(error[key]);
    if (nested !== null) return nested;
  }
  return null;
}

function describeRevert(
  error: unknown,
  interfaces: readonly Interface[],
): string {
  const data = revertData(error);
  if (data !== null) {
    for (const iface of interfaces) {
      try {
        const parsed = iface.parseError(data);
        if (parsed !== null) return parsed.name;
      } catch {
        continue;
      }
    }
    return `unknown selector ${data.slice(0, 10)} (${ethers.getBytes(data).length} bytes)`;
  }
  const message = error instanceof Error ? error.message : String(error);
  return message.slice(0, 256);
}

describe("NOX funded non-benchmark paid mesh", function () {
  this.timeout(900_000);

  let mesh: PaidMeshInfo;
  let deployment: DeploymentRecord;
  let sdk: PaidNoxModule;
  let client: PaidNoxClient;
  let chainProvider: JsonRpcProvider;
  let requestTimeoutMs: number;

  before(async function () {
    const meshPath = process.env["MESH_INFO_PATH"];
    const deploymentPath = process.env["DEPLOYMENT_RECORD_PATH"];
    const sdkRoot = process.env["NOX_SDK_DIR"];
    if (!meshPath || !deploymentPath || !sdkRoot) {
      if (process.env["REQUIRE_NOX_MESH"] === "1") {
        throw new Error(
          "paid mesh requires MESH_INFO_PATH, DEPLOYMENT_RECORD_PATH, and NOX_SDK_DIR",
        );
      }
      this.skip();
      return;
    }

    mesh = parsePaidMesh(meshPath);
    deployment = parseDeployment(deploymentPath);
    chainProvider = new ethers.JsonRpcProvider(mesh.rpc_url);
    requestTimeoutMs = Number(process.env["NOX_E2E_TIMEOUT_MS"] ?? "120000");
    if (!Number.isSafeInteger(requestTimeoutMs) || requestTimeoutMs <= 0) {
      throw new Error("NOX_E2E_TIMEOUT_MS must be a positive safe integer");
    }
    expect(mesh.chain_id).to.equal(31337);
    expect(ethers.getAddress(mesh.entry_point_address)).to.equal(
      ethers.getAddress(deployment.contracts.noxEntryPoint),
    );
    expect(ethers.getAddress(mesh.payment_adapter_address)).to.equal(
      ethers.getAddress(deployment.contracts.howlPaymentAdapter),
    );
    expect(ethers.getAddress(mesh.reward_pool_address)).to.equal(
      ethers.getAddress(deployment.contracts.noxRewardPool),
    );
    expect(ethers.getAddress(mesh.fee_asset_address)).to.equal(
      ethers.getAddress(deployment.contracts.stakingToken),
    );

    sdk = await loadPaidNoxModule(sdkRoot);
    const connected = await sdk.NoxClient.connect({
      seeds: [baseUrl(mesh.topology_urls[0]!)],
      ethRpcUrl: mesh.rpc_url,
      registryAddress: deployment.contracts.noxRegistry,
      powDifficulty: 0,
      timeoutMs: requestTimeoutMs,
      surbsPerRequest: 10,
    });
    requirePaidMethods(connected);
    client = connected;
  });

  after(function () {
    client?.disconnect();
    chainProvider?.destroy();
  });

  async function requestAndSubmit(
    label: string,
    wallet: TestWallet,
    paymentId: Fr,
    clientIntentId: string,
    actionTarget: string,
    actionData: string,
    actionGasLimit: bigint,
    expectedReturnData: string,
  ) {
    const selectedExit = client.selectPaidExit();
    expect(ethers.getAddress(selectedExit.id)).to.equal(
      ethers.getAddress(mesh.selected_exit.address),
    );
    const trackedAssets: string[] = [];
    const quoteRequest: PaidQuoteRequestV2 = {
      chainId: BigInt(mesh.chain_id),
      entryPoint: fixedBytes(mesh.entry_point_address, 20, "entry point"),
      clientIntentId: fixedBytes(clientIntentId, 32, "client intent"),
      paymentAdapter: fixedBytes(
        mesh.payment_adapter_address,
        20,
        "payment adapter",
      ),
      paymentId: fixedBytes(paymentId.toString(), 32, "payment ID"),
      feeAsset: fixedBytes(mesh.fee_asset_address, 20, "fee asset"),
      paymentGasLimit: HOWL_PAYMENT_GAS_LIMIT,
      actionTarget: fixedBytes(actionTarget, 20, "action target"),
      actionCalldataHash: fixedBytes(
        ethers.keccak256(actionData),
        32,
        "action hash",
      ),
      actionGasLimit,
      trackedAssetsHash: fixedBytes(
        ethers.keccak256(
          ethers.AbiCoder.defaultAbiCoder().encode(
            ["address[]"],
            [trackedAssets],
          ),
        ),
        32,
        "tracked assets hash",
      ),
      maximumTransactionGas: sdk.planPaidGas({
        paymentGasLimit: HOWL_PAYMENT_GAS_LIMIT,
        actionGasLimit,
        calldataGas: sdk.paidExecuteCalldata(
          ethers.getBytes(actionData),
          trackedAssets.length,
          HOWL_PAYMENT_DATA_LENGTH,
        ).gas,
      }).maximumTransactionGas,
      returnDataLimit: 256,
      validUntilUnix: BigInt(Math.floor(Date.now() / 1000) + 120),
    };
    // The exit stamps validAfter with the latest block timestamp, so a quiet chain shortens the quote.
    await chainProvider.send("evm_mine", []);
    const quoteRequestedAt = Date.now();
    const quoteResult = await client.requestPaidQuote(
      quoteRequest,
      selectedExit,
    );
    const quoteIssuedAt = Date.now();
    if (quoteResult.status !== "issued") {
      throw new Error(
        `paid quote rejected: ${quoteResult.code} (${quoteResult.detail})`,
      );
    }
    const quote = quoteForContract(quoteResult.quote);
    const executionId = ethers.hexlify(quoteResult.executionId);
    expect(ethers.getAddress(quoteResult.selectedExit.id)).to.equal(
      ethers.getAddress(mesh.selected_exit.address),
    );
    expect(ethers.getAddress(quote.exitAddress)).to.equal(
      ethers.getAddress(mesh.selected_exit.address),
    );
    const entryPoint = await ethers.getContractAt(
      "NoxEntryPoint",
      deployment.contracts.noxEntryPoint,
    );
    expect(await entryPoint.executionId(quote)).to.equal(executionId);
    const rewardPool = await ethers.getContractAt(
      "NoxRewardPool",
      deployment.contracts.noxRewardPool,
    );
    const feeToken = await ethers.getContractAt(
      "MockERC20",
      deployment.contracts.stakingToken,
    );
    const paymentPool = await ethers.getContractAt(
      "DarkPool",
      deployment.contracts.darkPool,
    );
    const exitCreditBefore = await rewardPool.claimableExit(
      mesh.selected_exit.address,
      mesh.fee_asset_address,
    );
    const networkOutstandingBefore = await rewardPool.networkOutstanding(
      mesh.fee_asset_address,
    );

    const totalFee = quote.exitFee + quote.networkFee;
    const paymentProof = await wallet.withdraw(totalFee, {
      recipient: deployment.contracts.howlPaymentAdapter,
      intentHash: howlPaymentIntent(executionId),
      inputNullifier: paymentId,
    });
    const paymentProvenAt = Date.now();
    const payment = buildHowlPayment(
      executionId,
      deployment.contracts.howlPaymentAdapter,
      paymentProof,
    );
    expect(payment.paymentId).to.equal(paymentId.toString());
    expect(payment.amount).to.equal(totalFee);
    expect(ethers.dataLength(payment.paymentData)).to.equal(
      HOWL_PAYMENT_DATA_LENGTH,
    );

    const calldata = entryPoint.interface.encodeFunctionData("execute", [
      quote,
      ethers.hexlify(quoteResult.exitSignature),
      actionData,
      trackedAssets,
      payment.paymentData,
    ]);
    const adapter = await ethers.getContractAt(
      "HowlPaymentAdapter",
      deployment.contracts.howlPaymentAdapter,
    );
    const sandboxFactory = await ethers.getContractFactory(
      "NoxExecutionSandbox",
    );
    const exactEstimate = await chainProvider.estimateGas({
      from: mesh.selected_exit.address,
      to: await entryPoint.getAddress(),
      data: calldata,
    });
    const bufferedGas = buffered(exactEstimate);
    expect(
      bufferedGas,
      `buffered gas ${bufferedGas} exceeds signed maximum ${quote.maximumTransactionGas}`,
    ).to.be.lessThanOrEqual(quote.maximumTransactionGas);
    const networkGasPrice = (await chainProvider.getFeeData()).gasPrice;
    if (networkGasPrice === null) {
      throw new Error("execution RPC did not return eth_gasPrice");
    }
    const bufferedInitialFee = buffered(networkGasPrice);
    expect(
      bufferedInitialFee,
      `buffered initial fee ${bufferedInitialFee} exceeds signed maximum ${quote.maximumFeePerGas}`,
    ).to.be.lessThanOrEqual(quote.maximumFeePerGas);
    try {
      const simulatedReturn = await chainProvider.call({
        from: mesh.selected_exit.address,
        to: await entryPoint.getAddress(),
        data: calldata,
        gasLimit: quote.maximumTransactionGas,
        gasPrice: quote.maximumFeePerGas,
      });
      const [simulatedOutcome] = entryPoint.interface.decodeFunctionResult(
        "execute",
        simulatedReturn,
      );
      expect(simulatedOutcome.success).to.equal(true);
    } catch (error: unknown) {
      throw new Error(
        `independent EntryPoint simulation failed: ${describeRevert(error, [
          entryPoint.interface,
          adapter.interface,
          paymentPool.interface,
          rewardPool.interface,
          sandboxFactory.interface,
        ])}`,
      );
    }
    const selectedExitNonceBefore = await chainProvider.getTransactionCount(
      mesh.selected_exit.address,
      "latest",
    );
    const paymentLeafIndex = await paymentPool.getNextLeafIndex();
    const preflightDoneAt = Date.now();
    const outcome = await client.submitPaidTransaction(
      quoteResult,
      ethers.getBytes(calldata),
    );
    const submittedAt = Date.now();
    if (outcome.status !== "submitted") {
      throw new Error(
        `paid submission rejected: ${outcome.code} (${outcome.detail})`,
      );
    }
    expect(ethers.hexlify(outcome.executionId)).to.equal(executionId);
    const transactionHash = ethers.hexlify(outcome.transactionHash);
    const receipt = await chainProvider.waitForTransaction(
      transactionHash,
      1,
      requestTimeoutMs,
    );
    if (!receipt)
      throw new Error(`paid transaction receipt missing: ${transactionHash}`);
    const includedAt = Date.now();
    expect(receipt.status).to.equal(1);
    const includedBlock = await chainProvider.getBlock(receipt.blockNumber);
    if (!includedBlock) throw new Error("paid transaction block missing");
    console.log(
      `[time] case=${label} quote=${quoteIssuedAt - quoteRequestedAt}ms` +
        ` proof=${paymentProvenAt - quoteIssuedAt}ms` +
        ` preflight=${preflightDoneAt - paymentProvenAt}ms` +
        ` submit=${submittedAt - preflightDoneAt}ms` +
        ` inclusion=${includedAt - submittedAt}ms` +
        ` validAfterToBlock=${BigInt(includedBlock.timestamp) - quote.validAfterUnix}s` +
        ` window=${quote.validUntilUnix - quote.validAfterUnix}s`,
    );
    const anonymousReceipt = await client.rpcCall("eth_getTransactionReceipt", [
      transactionHash,
    ]);
    if (!isRecord(anonymousReceipt)) {
      throw new Error("anonymous receipt response must be an object");
    }
    expect(
      requiredString(anonymousReceipt, "transactionHash", "anonymous receipt"),
    ).to.equal(transactionHash);
    expect(
      requiredString(anonymousReceipt, "status", "anonymous receipt"),
    ).to.equal("0x1");
    expect(
      ethers.getAddress(
        requiredString(anonymousReceipt, "from", "anonymous receipt"),
      ),
    ).to.equal(ethers.getAddress(mesh.selected_exit.address));
    expect(
      ethers.getAddress(
        requiredString(anonymousReceipt, "to", "anonymous receipt"),
      ),
    ).to.equal(ethers.getAddress(deployment.contracts.noxEntryPoint));

    const settlement = receipt.logs
      .map((log) => {
        try {
          return entryPoint.interface.parseLog(log);
        } catch {
          return null;
        }
      })
      .find((log) => log?.name === "PaidExecutionSettled");
    if (!settlement) throw new Error("PaidExecutionSettled event missing");
    expect(settlement.args.executionId).to.equal(executionId);
    expect(settlement.args.paymentId).to.equal(payment.paymentId);
    expect(settlement.args.exit).to.equal(
      ethers.getAddress(mesh.selected_exit.address),
    );
    expect(settlement.args.feeAsset).to.equal(
      ethers.getAddress(mesh.fee_asset_address),
    );
    expect(settlement.args.exitFee).to.equal(quote.exitFee);
    expect(settlement.args.networkFee).to.equal(quote.networkFee);
    expect(settlement.args.actionTarget).to.equal(
      ethers.getAddress(actionTarget),
    );
    expect(settlement.args.actionSuccess).to.equal(true);
    expect(settlement.args.returnDataLength).to.equal(
      BigInt(ethers.getBytes(expectedReturnData).length),
    );
    expect(settlement.args.returnPrefixHash).to.equal(
      ethers.keccak256(expectedReturnData),
    );
    expect(
      await rewardPool.claimableExit(
        mesh.selected_exit.address,
        mesh.fee_asset_address,
      ),
    ).to.equal(exitCreditBefore + quote.exitFee);
    expect(
      await rewardPool.networkOutstanding(mesh.fee_asset_address),
    ).to.equal(networkOutstandingBefore + quote.networkFee);
    expect(await feeToken.balanceOf(await entryPoint.getAddress())).to.equal(
      0n,
    );
    expect(
      await feeToken.balanceOf(deployment.contracts.howlPaymentAdapter),
    ).to.equal(0n);
    expect(
      await feeToken.allowance(
        deployment.contracts.howlPaymentAdapter,
        deployment.contracts.darkPool,
      ),
    ).to.equal(0n);
    expect(
      await feeToken.allowance(
        await entryPoint.getAddress(),
        await rewardPool.getAddress(),
      ),
    ).to.equal(0n);
    const sandboxAddress = await entryPoint.predictSandbox(
      ethers.hexlify(quoteResult.quote.clientIntentId),
    );
    const sandbox = await ethers.getContractAt(
      "NoxExecutionSandbox",
      sandboxAddress,
    );
    expect(await sandbox.finalized()).to.equal(true);
    expect(await feeToken.balanceOf(sandboxAddress)).to.equal(0n);
    expect(await ethers.provider.getBalance(sandboxAddress)).to.equal(0n);
    expect(await feeToken.allowance(sandboxAddress, actionTarget)).to.equal(0n);
    const paymentChangeFound = receipt.logs.some((log) => {
      try {
        const parsed = paymentPool.interface.parseLog(log);
        return (
          parsed?.name === "NewNote" &&
          parsed.args.commitment === paymentProof.publicInputs[8]
        );
      } catch {
        return false;
      }
    });
    expect(paymentChangeFound).to.equal(true);

    const trace = parseCallFrame(
      await chainProvider.send("debug_traceTransaction", [
        transactionHash,
        { tracer: "callTracer" },
      ]),
      "paid transaction trace",
    );
    const paymentFrame = findFrame(
      trace,
      ethers.getAddress(deployment.contracts.noxEntryPoint),
      ethers.getAddress(deployment.contracts.howlPaymentAdapter),
    );
    const actionFrame = findFrame(
      trace,
      ethers.getAddress(sandboxAddress),
      ethers.getAddress(actionTarget),
    );
    console.log(
      `[gas] case=${label} leaf=${paymentLeafIndex} payment=${paymentFrame.gasUsed}` +
        ` action=${actionFrame.gasUsed} total=${receipt.gasUsed}` +
        ` estimate=${exactEstimate} calldata=${ethers.dataLength(calldata)}`,
    );
    expect(paymentFrame.gasUsed).to.be.lessThan(quote.paymentGasLimit);
    expect(actionFrame.gasUsed).to.be.lessThan(quote.actionGasLimit);
    expect(paymentFrame.gasUsed + TREE_ALLOWANCE_GAS).to.be.lessThanOrEqual(
      HOWL_PAYMENT_GAS_LIMIT,
    );

    const duplicate = await client.submitPaidTransaction(
      quoteResult,
      ethers.getBytes(calldata),
    );
    expect(duplicate.status).to.equal("rejected");
    if (duplicate.status !== "rejected") {
      throw new Error("duplicate paid submission unexpectedly succeeded");
    }
    expect(duplicate.code).to.equal("DuplicateExecution");
    expect(
      await chainProvider.getTransactionCount(
        mesh.selected_exit.address,
        "latest",
      ),
    ).to.equal(selectedExitNonceBefore + 1);
    return {
      quote,
      executionId,
      transactionHash,
      receipt,
      paymentProof,
      paymentFrame,
      actionFrame,
    };
  }

  it("executes a pre-proven Howl withdrawal with an independent fee note", async function () {
    const [alice] = await ethers.getSigners();
    const darkPool = await ethers.getContractAt(
      "DarkPool",
      deployment.contracts.darkPool,
    );
    const token = await ethers.getContractAt(
      "MockERC20",
      deployment.contracts.stakingToken,
    );
    await token.mint(alice.address, ethers.parseEther("2000"));
    const wallet = await TestWallet.create(
      alice,
      darkPool,
      token,
      deployment.meta.startBlock,
    );
    await wallet.sync();
    expect(BigInt(wallet.tree.nextLeafIndex)).to.equal(
      await darkPool.getNextLeafIndex(),
    );
    const actionDeposit = await wallet.deposit(2n);
    const feeDeposit = await wallet.deposit(ethers.parseEther("1000"));
    await wallet.syncTree(actionDeposit.commitment);
    await wallet.syncTree(feeDeposit.commitment);
    await wallet.sync();
    const notes = wallet.utxoRepo.getUnspentNotes();
    expect(notes).to.have.length(2);

    const actionProof = await wallet.withdraw(1n, {
      recipient: alice.address,
      intentHash: toFr(1n),
      inputNullifier: notes[0]!.nullifier,
    });
    const actionData = darkPool.interface.encodeFunctionData("withdraw", [
      actionProof.proof,
      actionProof.publicInputs,
    ]);
    const aliceTokenBefore = await token.balanceOf(alice.address);
    const aliceNativeBefore = await chainProvider.getBalance(alice.address);
    const exitNativeBefore = await chainProvider.getBalance(
      mesh.selected_exit.address,
    );
    const submitted = await requestAndSubmit(
      "howl-withdraw",
      wallet,
      notes[1]!.nullifier,
      ethers.id("howl-paid-action"),
      deployment.contracts.darkPool,
      actionData,
      HOWL_WITHDRAW_ACTION_GAS_LIMIT,
      "0x",
    );

    expect(await token.balanceOf(alice.address)).to.equal(
      aliceTokenBefore + 1n,
    );
    expect(await chainProvider.getBalance(alice.address)).to.equal(
      aliceNativeBefore,
    );
    expect(
      await chainProvider.getBalance(mesh.selected_exit.address),
    ).to.be.lessThan(exitNativeBefore);
    const chainTransaction = await chainProvider.getTransaction(
      submitted.transactionHash,
    );
    expect(chainTransaction?.from).to.equal(
      ethers.getAddress(mesh.selected_exit.address),
    );
    expect(chainTransaction?.to).to.equal(
      ethers.getAddress(deployment.contracts.noxEntryPoint),
    );
    expect(
      await darkPool.isNullifierSpent(actionProof.publicInputs[5]),
    ).to.equal(true);
    expect(
      await darkPool.isNullifierSpent(submitted.paymentProof.publicInputs[5]),
    ).to.equal(true);

    const noteCommitments = submitted.receipt.logs
      .map((log) => {
        try {
          return darkPool.interface.parseLog(log);
        } catch {
          return null;
        }
      })
      .filter((log) => log?.name === "NewNote")
      .map((log) => log!.args.commitment as string);
    expect(noteCommitments).to.deep.equal([
      submitted.paymentProof.publicInputs[8],
      actionProof.publicInputs[8],
    ]);
    expect(
      submitted.actionFrame.gasUsed + TREE_ALLOWANCE_GAS,
    ).to.be.lessThanOrEqual(HOWL_WITHDRAW_ACTION_GAS_LIMIT);
  });

  it("executes generic opaque calldata through the same paid Nox interface", async function () {
    const [, bob] = await ethers.getSigners();
    const darkPool = await ethers.getContractAt(
      "DarkPool",
      deployment.contracts.darkPool,
    );
    const token = await ethers.getContractAt(
      "MockERC20",
      deployment.contracts.stakingToken,
    );
    await token.mint(bob.address, ethers.parseEther("1000"));
    const wallet = await TestWallet.create(
      bob,
      darkPool,
      token,
      deployment.meta.startBlock,
    );
    await wallet.sync();
    expect(BigInt(wallet.tree.nextLeafIndex)).to.equal(
      await darkPool.getNextLeafIndex(),
    );
    const deposit = await wallet.deposit(ethers.parseEther("1000"));
    await wallet.syncTree(deposit.commitment);
    await wallet.sync();
    const paymentNote = wallet.utxoRepo.getUnspentNotes()[0];
    if (!paymentNote) throw new Error("generic paid action fee note missing");

    const target = await (
      await ethers.getContractFactory("NoxActionTarget")
    ).deploy();
    const actionData = target.interface.encodeFunctionData("setValue", [4242]);
    await requestAndSubmit(
      "generic-call",
      wallet,
      paymentNote.nullifier,
      ethers.id("generic-paid-action"),
      await target.getAddress(),
      actionData,
      GENERIC_ACTION_GAS_LIMIT,
      ethers.AbiCoder.defaultAbiCoder().encode(["uint256"], [4242n]),
    );
    expect(await target.value()).to.equal(4242n);
  });

  it("executes a note-funded call bundle through BundleExecutor as the paid action", async function () {
    const [, , owner] = await ethers.getSigners();
    const darkPool = await ethers.getContractAt(
      "DarkPool",
      deployment.contracts.darkPool,
    );
    const token = await ethers.getContractAt(
      "MockERC20",
      deployment.contracts.stakingToken,
    );
    const executor = await ethers.getContractAt(
      "BundleExecutor",
      deployment.contracts.bundleExecutor,
    );
    const tokenAddress = await token.getAddress();
    const executorAddress = await executor.getAddress();
    const bundleValue = 10n;
    const firstShare = 6n;
    await token.mint(
      owner.address,
      ethers.parseEther("1000") + bundleValue + 1n,
    );
    const wallet = await TestWallet.create(
      owner,
      darkPool,
      token,
      deployment.meta.startBlock,
    );
    await wallet.sync();
    expect(BigInt(wallet.tree.nextLeafIndex)).to.equal(
      await darkPool.getNextLeafIndex(),
    );
    const bundleDeposit = await wallet.deposit(bundleValue + 1n);
    const feeDeposit = await wallet.deposit(ethers.parseEther("1000"));
    await wallet.syncTree(bundleDeposit.commitment);
    await wallet.syncTree(feeDeposit.commitment);
    await wallet.sync();
    const notes = wallet.utxoRepo.getUnspentNotes();
    expect(notes).to.have.length(2);
    const bundleNote = notes.find((n) => n.note.value === bundleValue + 1n);
    const feeNote = notes.find(
      (n) => n.note.value === ethers.parseEther("1000"),
    );
    if (!bundleNote || !feeNote) throw new Error("bundle case notes missing");

    const target = await (
      await ethers.getContractFactory("NoxActionTarget")
    ).deploy();
    const targetAddress = await target.getAddress();
    const carol = ethers.Wallet.createRandom().address;
    const dave = ethers.Wallet.createRandom().address;
    const boundCall = (callTarget: string, data: string): BundleCall => ({
      target: callTarget,
      data,
      value: 0n,
      requireSuccess: true,
      approveToken: ZERO_ADDRESS,
      approveAmount: 0n,
      gasLimit: 100_000n,
      returnDataLimit: 32n,
    });
    const latestBlock = await chainProvider.getBlock("latest");
    if (!latestBlock) throw new Error("latest block missing");
    const bundle = buildBundle(
      {
        chainId: BigInt(mesh.chain_id),
        executor: executorAddress,
        darkPool: await darkPool.getAddress(),
      },
      [
        boundCall(
          tokenAddress,
          token.interface.encodeFunctionData("transfer", [carol, firstShare]),
        ),
        boundCall(
          tokenAddress,
          token.interface.encodeFunctionData("transfer", [
            dave,
            bundleValue - firstShare,
          ]),
        ),
        boundCall(
          targetAddress,
          target.interface.encodeFunctionData("setValue", [4242]),
        ),
      ],
      BigInt(latestBlock.timestamp) + 600n,
      [tokenAddress],
      [carol, dave],
    );
    expect(
      await executor.intentHashOf(
        bundle.boundCalls,
        bundle.deadline,
        bundle.trackedAssets,
        bundle.recipients,
      ),
    ).to.equal(bundle.intentHash.toBigInt());

    const bundleProof = await wallet.withdraw(bundleValue, {
      recipient: executorAddress,
      intentHash: bundle.intentHash,
      inputNullifier: bundleNote.nullifier,
    });
    const actionData = encodeBundleExecute(bundle, bundleProof);
    expect(actionData).to.equal(
      executor.interface.encodeFunctionData("execute", [
        bundleProof.proof,
        bundleProof.publicInputs,
        bundle.boundCalls,
        bundle.deadline,
        bundle.trackedAssets,
        bundle.recipients,
      ]),
    );
    const bundleNullifier = bundleProof.publicInputs[5]!;
    expect(bundleNullifier).to.equal(bundleNote.nullifier.toString());
    expect(bundleNullifier).to.not.equal(feeNote.nullifier.toString());

    const executorTokenBefore = await token.balanceOf(executorAddress);
    const ownerNativeBefore = await chainProvider.getBalance(owner.address);
    const submitted = await requestAndSubmit(
      "howl-bundle",
      wallet,
      feeNote.nullifier,
      ethers.id("bundle-paid-action"),
      executorAddress,
      actionData,
      bundleActionGasLimit(bundle),
      "0x",
    );

    const poolAddress = await darkPool.getAddress();
    const withdrawFrame = findFrame(
      submitted.actionFrame,
      executorAddress,
      poolAddress,
    );
    const boundCallGas = submitted.actionFrame.calls
      .filter((frame) => frame.type === "CALL" && frame.to !== poolAddress)
      .map((frame) => frame.gasUsed);
    expect(boundCallGas).to.have.length(bundle.boundCalls.length);
    console.log(
      `[gas] case=howl-bundle withdraw=${withdrawFrame.gasUsed}` +
        ` boundCalls=${boundCallGas.join(",")}` +
        ` limit=${bundleActionGasLimit(bundle)}`,
    );
    expect(
      submitted.actionFrame.gasUsed + TREE_ALLOWANCE_GAS,
    ).to.be.lessThanOrEqual(bundleActionGasLimit(bundle));

    const executorLogs = submitted.receipt.logs
      .filter((log) => log.address === executorAddress)
      .map((log) => executor.interface.parseLog(log));
    expect(executorLogs.map((log) => log?.name)).to.deep.equal([
      "CallExecuted",
      "CallExecuted",
      "CallExecuted",
      "BundleExecuted",
    ]);
    expect(
      executorLogs.slice(0, 3).map((log) => log?.args.index),
    ).to.deep.equal([0n, 1n, 2n]);
    const executed = executorLogs[3];
    expect(executed?.args.nullifier).to.equal(bundleNullifier);
    expect(executed?.args.intentHash).to.equal(bundle.intentHash.toBigInt());
    expect(executed?.args.callCount).to.equal(3n);

    expect(await token.balanceOf(carol)).to.equal(firstShare);
    expect(await token.balanceOf(dave)).to.equal(bundleValue - firstShare);
    expect(await target.value()).to.equal(4242n);
    expect(await token.balanceOf(executorAddress)).to.equal(
      executorTokenBefore,
    );
    for (const spender of [tokenAddress, targetAddress, carol, dave]) {
      expect(await token.allowance(executorAddress, spender)).to.equal(0n);
    }
    expect(await darkPool.isNullifierSpent(bundleNullifier)).to.equal(true);
    expect(
      await darkPool.isNullifierSpent(submitted.paymentProof.publicInputs[5]),
    ).to.equal(true);
    expect(await chainProvider.getBalance(owner.address)).to.equal(
      ownerNativeBefore,
    );
    const chainTransaction = await chainProvider.getTransaction(
      submitted.transactionHash,
    );
    expect(chainTransaction?.from).to.equal(
      ethers.getAddress(mesh.selected_exit.address),
    );
    expect(chainTransaction?.to).to.equal(
      ethers.getAddress(deployment.contracts.noxEntryPoint),
    );
    const noteCommitments = submitted.receipt.logs
      .map((log) => {
        try {
          return darkPool.interface.parseLog(log);
        } catch {
          return null;
        }
      })
      .filter((log) => log?.name === "NewNote")
      .map((log) => log!.args.commitment as string);
    expect(noteCommitments).to.deep.equal([
      submitted.paymentProof.publicInputs[8],
      bundleProof.publicInputs[8],
    ]);
  });

  it("pays a call and a call bundle through executePaid with Howl fee notes", async function () {
    const [, , , payer] = await ethers.getSigners();
    const darkPool = await ethers.getContractAt(
      "DarkPool",
      deployment.contracts.darkPool,
    );
    const token = await ethers.getContractAt(
      "MockERC20",
      deployment.contracts.stakingToken,
    );
    const executor = await ethers.getContractAt(
      "BundleExecutor",
      deployment.contracts.bundleExecutor,
    );
    const rewardPool = await ethers.getContractAt(
      "NoxRewardPool",
      deployment.contracts.noxRewardPool,
    );
    const tokenAddress = await token.getAddress();
    const executorAddress = await executor.getAddress();
    const feeNoteValue = ethers.parseEther("1000");
    const bundleValue = 10n;
    const firstShare = 6n;
    await token.mint(payer.address, 2n * feeNoteValue + bundleValue + 1n);
    const wallet = await TestWallet.create(
      payer,
      darkPool,
      token,
      deployment.meta.startBlock,
    );
    await wallet.sync();
    expect(BigInt(wallet.tree.nextLeafIndex)).to.equal(
      await darkPool.getNextLeafIndex(),
    );
    for (const value of [bundleValue + 1n, feeNoteValue, feeNoteValue]) {
      await wallet.syncTree((await wallet.deposit(value)).commitment);
    }
    await wallet.sync();
    const notes = wallet.utxoRepo.getUnspentNotes();
    const bundleNote = notes.find((n) => n.note.value === bundleValue + 1n);
    const feeNotes = notes.filter((n) => n.note.value === feeNoteValue);
    if (!bundleNote || feeNotes.length !== 2) {
      throw new Error("helper case notes missing");
    }

    const preflight = sdk.rpcChainReader((method, params) =>
      chainProvider.send(method, params),
    );
    const pay = async (
      label: string,
      feeNote: (typeof feeNotes)[number],
      action: { target: string; data: string; gasLimit?: bigint },
    ) => {
      const exitCreditBefore = await rewardPool.claimableExit(
        mesh.selected_exit.address,
        mesh.fee_asset_address,
      );
      // The exit stamps validAfter with the latest block timestamp, so a quiet chain shortens the quote.
      await chainProvider.send("evm_mine", []);
      const result = await sdk.executePaid(client, {
        chainId: BigInt(mesh.chain_id),
        entryPoint: mesh.entry_point_address,
        action: { ...action, data: ethers.getBytes(action.data) },
        payment: howlPaymentSource({
          adapter: deployment.contracts.howlPaymentAdapter,
          feeAsset: mesh.fee_asset_address,
          feeNoteNullifier: feeNote.nullifier.toString(),
          feeNoteValue: feeNote.note.value,
          proveFeeWithdraw: (amount, recipient, intentHash) =>
            wallet.withdraw(amount, {
              recipient,
              intentHash,
              inputNullifier: feeNote.nullifier,
            }),
        }),
        maxTotalFee: feeNote.note.value,
        intentSalt: ethers.randomBytes(32),
        preflight,
      });
      if (result.status !== "settled") {
        throw new Error(
          `executePaid ${label}: ${result.status} ${result.stage ?? ""} ${result.code ?? ""} ${result.detail ?? ""}`,
        );
      }
      expect(result.exit).to.equal(
        ethers.getAddress(mesh.selected_exit.address),
      );
      const receipt = await chainProvider.getTransactionReceipt(
        result.transactionHash,
      );
      if (!receipt) throw new Error(`${label} receipt missing`);
      expect(receipt.status).to.equal(1);
      expect(receipt.from).to.equal(
        ethers.getAddress(mesh.selected_exit.address),
      );
      expect(receipt.gasUsed).to.be.lessThan(result.maximumTransactionGas);
      expect(
        await darkPool.isNullifierSpent(feeNote.nullifier.toString()),
      ).to.equal(true);
      expect(
        await rewardPool.claimableExit(
          mesh.selected_exit.address,
          mesh.fee_asset_address,
        ),
      ).to.equal(exitCreditBefore + result.exitFee);
      console.log(
        `[gas] case=${label} total=${receipt.gasUsed} cap=${result.maximumTransactionGas}` +
          ` fee=${result.exitFee + result.networkFee}`,
      );
      console.log(
        `[time] case=${label} ${Object.entries(result.timings)
          .map(([stage, ms]) => `${stage}=${ms}ms`)
          .join(" ")}`,
      );
      return receipt;
    };

    const target = await (
      await ethers.getContractFactory("NoxActionTarget")
    ).deploy();
    const targetAddress = await target.getAddress();
    await pay("helper-call", feeNotes[0]!, {
      target: targetAddress,
      data: target.interface.encodeFunctionData("setValue", [4242]),
    });
    expect(await target.value()).to.equal(4242n);

    const carol = ethers.Wallet.createRandom().address;
    const dave = ethers.Wallet.createRandom().address;
    const transfer = (recipient: string, amount: bigint): BundleCall => ({
      target: tokenAddress,
      data: token.interface.encodeFunctionData("transfer", [recipient, amount]),
      value: 0n,
      requireSuccess: true,
      approveToken: ZERO_ADDRESS,
      approveAmount: 0n,
      gasLimit: 100_000n,
      returnDataLimit: 32n,
    });
    const latestBlock = await chainProvider.getBlock("latest");
    if (!latestBlock) throw new Error("latest block missing");
    const bundle = buildBundle(
      {
        chainId: BigInt(mesh.chain_id),
        executor: executorAddress,
        darkPool: await darkPool.getAddress(),
      },
      [transfer(carol, firstShare), transfer(dave, bundleValue - firstShare)],
      BigInt(latestBlock.timestamp) + 600n,
      [tokenAddress],
      [carol, dave],
    );
    const bundleProof = await wallet.withdraw(bundleValue, {
      recipient: executorAddress,
      intentHash: bundle.intentHash,
      inputNullifier: bundleNote.nullifier,
    });
    const receipt = await pay("helper-bundle", feeNotes[1]!, {
      target: executorAddress,
      data: encodeBundleExecute(bundle, bundleProof),
      gasLimit: bundleActionGasLimit(bundle),
    });
    expect(await token.balanceOf(carol)).to.equal(firstShare);
    expect(await token.balanceOf(dave)).to.equal(bundleValue - firstShare);
    expect(
      await darkPool.isNullifierSpent(bundleNote.nullifier.toString()),
    ).to.equal(true);
    expect(
      receipt.logs
        .filter((log) => log.address === executorAddress)
        .map((log) => executor.interface.parseLog(log)?.name),
    ).to.deep.equal(["CallExecuted", "CallExecuted", "BundleExecuted"]);
  });
});
