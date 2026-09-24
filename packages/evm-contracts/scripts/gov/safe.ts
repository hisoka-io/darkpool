/**
 * Safe v1.4.1 helpers for the governance scripts: create a Safe, sign and execute a Safe transaction with
 * locally held owner keys, and route calls through the OZ TimelockController the Gov Safe proposes to.
 *
 * Addresses and runtime code hashes are the "canonical" v1.4.1 deployments from
 * github.com/safe-global/safe-deployments (src/assets/v1.4.1), deployed at the same address on every chain
 * they support, Arbitrum Sepolia (421614) included. The code hashes are pinned so a chain where those
 * addresses hold anything else is refused before a Safe is created or trusted.
 */

import { ethers } from "ethers";
import * as fs from "fs";

export const SAFE_VERSION = "1.4.1";

export const SAFE_V141 = {
  proxyFactory: {
    address: "0x4e1DCf7AD4e460CfD30791CCC4F9c8a4f820ec67",
    codeHash:
      "0x50c3cdc4074750a7a974204a716c999edd37482f907608d960b2b025ee0b3317",
  },
  safeL2Singleton: {
    address: "0x29fcB43b46531BcA003ddC8FCB67FFE91900C762",
    codeHash:
      "0xb1f926978a0f44a2c0ec8fe822418ae969bd8c3f18d61e5103100339894f81ff",
  },
  fallbackHandler: {
    address: "0xfd0732Dc9E303f09fCEf3a7388Ad10A83459Ec99",
    codeHash:
      "0x7c6007a5d711cea8dfd5d91f5940ec29c7f200fe511eb1fc1397b367af3c42f9",
  },
  multiSendCallOnly: {
    address: "0x9641d764fc13c8B624c04430C7356C1C7C8102e2",
    codeHash:
      "0xecd5bd14a08c5d2122379900b2f272bdf107a7e92423c10dd5fe3254386c9939",
  },
} as const;

// Safe storage: slot 0 is the singleton; the other two are keccak256 of the manager's label.
const SINGLETON_SLOT = 0n;
const FALLBACK_HANDLER_SLOT = ethers.id("fallback_manager.handler.address");
const GUARD_SLOT = ethers.id("guard_manager.guard.address");
const SENTINEL = "0x0000000000000000000000000000000000000001";

const SAFE_ABI = [
  "function setup(address[] _owners, uint256 _threshold, address to, bytes data, address fallbackHandler, address paymentToken, uint256 payment, address paymentReceiver)",
  "function VERSION() view returns (string)",
  "function getOwners() view returns (address[])",
  "function getThreshold() view returns (uint256)",
  "function nonce() view returns (uint256)",
  "function getModulesPaginated(address start, uint256 pageSize) view returns (address[] array, address next)",
  "function getTransactionHash(address to, uint256 value, bytes data, uint8 operation, uint256 safeTxGas, uint256 baseGas, uint256 gasPrice, address gasToken, address refundReceiver, uint256 _nonce) view returns (bytes32)",
  "function execTransaction(address to, uint256 value, bytes data, uint8 operation, uint256 safeTxGas, uint256 baseGas, uint256 gasPrice, address gasToken, address refundReceiver, bytes signatures) payable returns (bool)",
  "event ExecutionSuccess(bytes32 indexed txHash, uint256 payment)",
  "event ExecutionFailure(bytes32 indexed txHash, uint256 payment)",
];
const FACTORY_ABI = [
  "function proxyCreationCode() pure returns (bytes)",
  "function createProxyWithNonce(address _singleton, bytes initializer, uint256 saltNonce) returns (address proxy)",
  "event ProxyCreation(address indexed proxy, address singleton)",
];
const MULTI_SEND_ABI = ["function multiSend(bytes transactions) payable"];
export const TIMELOCK_ABI = [
  "function getMinDelay() view returns (uint256)",
  "function hashOperationBatch(address[] targets, uint256[] values, bytes[] payloads, bytes32 predecessor, bytes32 salt) pure returns (bytes32)",
  "function getOperationState(bytes32 id) view returns (uint8)",
  "function getTimestamp(bytes32 id) view returns (uint256)",
  "function scheduleBatch(address[] targets, uint256[] values, bytes[] payloads, bytes32 predecessor, bytes32 salt, uint256 delay)",
  "function executeBatch(address[] targets, uint256[] values, bytes[] payloads, bytes32 predecessor, bytes32 salt) payable",
];

export enum Operation {
  Call = 0,
  DelegateCall = 1,
}

// OZ TimelockController.OperationState.
enum OperationState {
  Unset = 0,
  Waiting = 1,
  Ready = 2,
  Done = 3,
}

export interface SafeCall {
  readonly to: string;
  readonly value: bigint;
  readonly data: string;
}

export interface SafeConfig {
  readonly owners: readonly string[];
  readonly threshold: number;
}

/** Owner signing keys by checksummed address. Never logged or serialized. */
export type OwnerKeys = ReadonlyMap<string, ethers.SigningKey>;

type Log = (line: string) => void;

function asRecord(value: unknown, where: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`${where} must be a JSON object.`);
  }
  return value as Record<string, unknown>;
}

function checksummed(value: unknown, where: string): string {
  if (typeof value !== "string" || !ethers.isAddress(value)) {
    throw new Error(`${where} is not a valid address.`);
  }
  const address = ethers.getAddress(value);
  if (address === ethers.ZeroAddress) {
    throw new Error(`${where} must be non-zero.`);
  }
  return address;
}

/**
 * Loads `{ "owners": [{ "address": "0x..", "privateKey": "0x..", "label"?: ".." }] }`. The file must be
 * readable by its owner only, and no key material reaches an error message: a JSON.parse error quotes the
 * surrounding source text, so it is replaced rather than wrapped.
 */
export function loadOwnerKeys(file: string): OwnerKeys {
  if (!fs.existsSync(file)) {
    throw new Error(`owner keys file ${file} does not exist.`);
  }
  const mode = fs.statSync(file).mode & 0o777;
  if ((mode & 0o077) !== 0) {
    throw new Error(
      `owner keys file ${file} is readable by others (mode ${mode.toString(8)}); run chmod 600 ${file}.`,
    );
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(fs.readFileSync(file, "utf8"));
  } catch {
    throw new Error(`owner keys file ${file} is not valid JSON.`);
  }
  const owners = asRecord(parsed, `owner keys file ${file}`).owners;
  if (!Array.isArray(owners) || owners.length === 0) {
    throw new Error(
      `owner keys file ${file} needs a non-empty "owners" array.`,
    );
  }
  const keys = new Map<string, ethers.SigningKey>();
  owners.forEach((entry, index) => {
    const where = `owner keys file ${file}, owners[${index}]`;
    const owner = asRecord(entry, where);
    const rawKey = owner.privateKey;
    if (
      typeof rawKey !== "string" ||
      !/^0x[0-9a-fA-F]{64}$/.test(rawKey.trim())
    ) {
      throw new Error(
        `${where}.privateKey must be a 0x-prefixed 32-byte hex string.`,
      );
    }
    let key: ethers.SigningKey;
    try {
      key = new ethers.SigningKey(rawKey.trim());
    } catch {
      throw new Error(`${where}.privateKey is not a valid secp256k1 key.`);
    }
    const derived = ethers.computeAddress(key.publicKey);
    if (owner.address !== undefined) {
      const declared = checksummed(owner.address, `${where}.address`);
      if (declared !== derived) {
        throw new Error(
          `${where}.address ${declared} does not match its privateKey (derives ${derived}).`,
        );
      }
    }
    if (keys.has(derived)) {
      throw new Error(`${where} repeats owner ${derived}.`);
    }
    keys.set(derived, key);
  });
  return keys;
}

/** Refuses a chain where the canonical Safe v1.4.1 addresses do not hold the canonical code. */
export async function assertCanonicalSafeStack(
  provider: ethers.Provider,
): Promise<void> {
  for (const [name, { address, codeHash }] of Object.entries(SAFE_V141)) {
    const code = await provider.getCode(address);
    if (code === "0x") {
      throw new Error(
        `Safe v${SAFE_VERSION} ${name} has no code at ${address} on this chain.`,
      );
    }
    if (ethers.keccak256(code) !== codeHash) {
      throw new Error(
        `Safe v${SAFE_VERSION} ${name} at ${address} does not match the canonical runtime code hash ${codeHash}.`,
      );
    }
  }
}

export function validateSafeConfig(config: SafeConfig, label: string): void {
  if (config.owners.length === 0) {
    throw new Error(`${label}: owners must be non-empty.`);
  }
  const seen = new Set<string>();
  for (const owner of config.owners) {
    const address = checksummed(owner, `${label} owner ${owner}`);
    if (address === SENTINEL) {
      throw new Error(`${label}: owner ${address} is the Safe sentinel.`);
    }
    if (seen.has(address)) {
      throw new Error(`${label}: owner ${address} is listed twice.`);
    }
    seen.add(address);
  }
  if (
    !Number.isInteger(config.threshold) ||
    config.threshold < 1 ||
    config.threshold > config.owners.length
  ) {
    throw new Error(
      `${label}: threshold ${config.threshold} must be an integer in [1, ${config.owners.length}].`,
    );
  }
}

export function safeInitializer(config: SafeConfig): string {
  return new ethers.Interface(SAFE_ABI).encodeFunctionData("setup", [
    config.owners.map((owner) => ethers.getAddress(owner)),
    config.threshold,
    ethers.ZeroAddress,
    "0x",
    SAFE_V141.fallbackHandler.address,
    ethers.ZeroAddress,
    0,
    ethers.ZeroAddress,
  ]);
}

/** The CREATE2 address SafeProxyFactory.createProxyWithNonce will produce for this setup and salt nonce. */
export async function predictSafeAddress(
  provider: ethers.Provider,
  config: SafeConfig,
  saltNonce: bigint,
): Promise<string> {
  const factory = new ethers.Contract(
    SAFE_V141.proxyFactory.address,
    FACTORY_ABI,
    provider,
  );
  const creationCode: string = await factory.proxyCreationCode();
  const salt = ethers.solidityPackedKeccak256(
    ["bytes32", "uint256"],
    [ethers.keccak256(safeInitializer(config)), saltNonce],
  );
  const initCode = ethers.concat([
    creationCode,
    ethers.AbiCoder.defaultAbiCoder().encode(
      ["uint256"],
      [SAFE_V141.safeL2Singleton.address],
    ),
  ]);
  return ethers.getCreate2Address(
    SAFE_V141.proxyFactory.address,
    salt,
    ethers.keccak256(initCode),
  );
}

async function storedAddress(
  provider: ethers.Provider,
  address: string,
  slot: bigint | string,
): Promise<string> {
  const raw = await provider.getStorage(address, slot);
  return ethers.getAddress(ethers.dataSlice(raw, 12));
}

/**
 * Asserts a deployed Safe is exactly the configured one: canonical SafeL2 singleton and fallback handler,
 * the owner set and threshold, and no module or guard that could act around the owners.
 */
export async function assertSafeState(
  provider: ethers.Provider,
  address: string,
  config: SafeConfig,
  label: string,
): Promise<void> {
  const safe = new ethers.Contract(address, SAFE_ABI, provider);
  const problems: string[] = [];
  const version: string = await safe.VERSION();
  if (version !== SAFE_VERSION) problems.push(`VERSION is ${version}`);
  const singleton = await storedAddress(provider, address, SINGLETON_SLOT);
  if (singleton !== SAFE_V141.safeL2Singleton.address) {
    problems.push(`singleton is ${singleton}`);
  }
  const handler = await storedAddress(provider, address, FALLBACK_HANDLER_SLOT);
  if (handler !== SAFE_V141.fallbackHandler.address) {
    problems.push(`fallback handler is ${handler}`);
  }
  const guard = await storedAddress(provider, address, GUARD_SLOT);
  if (guard !== ethers.ZeroAddress) problems.push(`guard ${guard} is set`);
  const [modules] = await safe.getModulesPaginated(SENTINEL, 10);
  if ((modules as string[]).length > 0) {
    problems.push(`modules enabled: ${(modules as string[]).join(", ")}`);
  }
  const owners = ((await safe.getOwners()) as string[]).map((owner) =>
    ethers.getAddress(owner),
  );
  const expected = config.owners.map((owner) => ethers.getAddress(owner));
  const sameOwners =
    owners.length === expected.length &&
    expected.every((owner) => owners.includes(owner));
  if (!sameOwners) problems.push(`owners are ${owners.join(", ")}`);
  const threshold = Number(await safe.getThreshold());
  if (threshold !== config.threshold)
    problems.push(`threshold is ${threshold}`);
  if (problems.length > 0) {
    throw new Error(
      `${label} Safe ${address} is not the configured ${config.threshold}-of-${config.owners.length}: ${problems.join("; ")}.`,
    );
  }
}

export interface EnsuredSafe {
  readonly address: string;
  readonly created: boolean;
  readonly txHash: string | null;
  readonly gasUsed: bigint;
}

/** Creates the Safe, or adopts it when the deterministic address already holds exactly this Safe. */
export async function ensureSafe(
  submitter: ethers.Signer,
  config: SafeConfig,
  saltNonce: bigint,
  label: string,
  log: Log,
): Promise<EnsuredSafe> {
  const provider = submitter.provider;
  if (provider === null) throw new Error("submitter has no provider.");
  validateSafeConfig(config, label);
  const predicted = await predictSafeAddress(provider, config, saltNonce);
  if ((await provider.getCode(predicted)) !== "0x") {
    await assertSafeState(provider, predicted, config, label);
    log(`  ${label}: ${predicted} already exists with this configuration.`);
    return { address: predicted, created: false, txHash: null, gasUsed: 0n };
  }
  const factory = new ethers.Contract(
    SAFE_V141.proxyFactory.address,
    FACTORY_ABI,
    submitter,
  );
  const tx: ethers.ContractTransactionResponse =
    await factory.createProxyWithNonce(
      SAFE_V141.safeL2Singleton.address,
      safeInitializer(config),
      saltNonce,
    );
  const receipt = await tx.wait();
  if (receipt === null || receipt.status !== 1) {
    throw new Error(`${label} Safe creation ${tx.hash} did not succeed.`);
  }
  const created = receipt.logs
    .map((entry) => {
      try {
        return factory.interface.parseLog(entry);
      } catch {
        return null;
      }
    })
    .find((parsed) => parsed?.name === "ProxyCreation");
  const proxy =
    created === undefined || created === null
      ? null
      : ethers.getAddress(created.args.proxy as string);
  if (proxy !== predicted) {
    throw new Error(
      `${label} Safe creation ${tx.hash} emitted proxy ${proxy}, expected ${predicted}.`,
    );
  }
  await assertSafeState(provider, predicted, config, label);
  log(
    `  ${label}: created ${predicted} (tx ${tx.hash}, gas ${receipt.gasUsed}).`,
  );
  return {
    address: predicted,
    created: true,
    txHash: tx.hash,
    gasUsed: receipt.gasUsed,
  };
}

/** One DELEGATECALL-able MultiSendCallOnly payload running `calls` in order as CALLs from the Safe. */
export function multiSendCallOnly(calls: readonly SafeCall[]): SafeCall {
  if (calls.length === 0) throw new Error("multiSend needs at least one call.");
  const packed = ethers.concat(
    calls.map((call) =>
      ethers.solidityPacked(
        ["uint8", "address", "uint256", "uint256", "bytes"],
        [
          Operation.Call,
          call.to,
          call.value,
          ethers.dataLength(call.data),
          call.data,
        ],
      ),
    ),
  );
  return {
    to: SAFE_V141.multiSendCallOnly.address,
    value: 0n,
    data: new ethers.Interface(MULTI_SEND_ABI).encodeFunctionData("multiSend", [
      packed,
    ]),
  };
}

export interface SafeExecution {
  readonly safe: string;
  readonly call: SafeCall;
  readonly operation: Operation;
  readonly keys: OwnerKeys;
  readonly submitter: ethers.Signer;
  /** Simulate with eth_call instead of sending; signatures are still produced and checked by the Safe. */
  readonly dryRun: boolean;
  readonly label: string;
  readonly log: Log;
}

export interface SafeExecutionResult {
  readonly safeTxHash: string;
  readonly txHash: string | null;
  readonly gasUsed: bigint;
}

/**
 * Signs `call` with exactly `threshold` owner keys (ascending owner address, as Safe's checkNSignatures
 * requires) and submits execTransaction from `submitter`. safeTxGas and gasPrice are zero, so an inner
 * revert reverts the whole transaction instead of burning the Safe nonce.
 */
export async function execSafeTransaction(
  execution: SafeExecution,
): Promise<SafeExecutionResult> {
  const { call, operation, keys, submitter, dryRun, label, log } = execution;
  const provider = submitter.provider;
  if (provider === null) throw new Error("submitter has no provider.");
  if (
    operation === Operation.DelegateCall &&
    call.to !== SAFE_V141.multiSendCallOnly.address
  ) {
    throw new Error(
      `${label}: DELEGATECALL is allowed only into MultiSendCallOnly ${SAFE_V141.multiSendCallOnly.address}.`,
    );
  }
  const safeAddress = ethers.getAddress(execution.safe);
  const safe = new ethers.Contract(safeAddress, SAFE_ABI, submitter);
  const owners = ((await safe.getOwners()) as string[]).map((owner) =>
    ethers.getAddress(owner),
  );
  const threshold = Number(await safe.getThreshold());
  const signers = owners
    .filter((owner) => keys.has(owner))
    .sort((a, b) => (BigInt(a) < BigInt(b) ? -1 : 1))
    .slice(0, threshold);
  if (signers.length < threshold) {
    throw new Error(
      `${label}: Safe ${safeAddress} needs ${threshold} owner signatures and the keys file holds ${signers.length} of its owners (${owners.join(", ")}).`,
    );
  }

  const nonce: bigint = await safe.nonce();
  const txArgs = [
    call.to,
    call.value,
    call.data,
    operation,
    0n,
    0n,
    0n,
    ethers.ZeroAddress,
    ethers.ZeroAddress,
  ] as const;
  const safeTxHash: string = await safe.getTransactionHash(...txArgs, nonce);
  const { chainId } = await provider.getNetwork();
  const localHash = ethers.TypedDataEncoder.hash(
    { chainId, verifyingContract: safeAddress },
    {
      SafeTx: [
        { type: "address", name: "to" },
        { type: "uint256", name: "value" },
        { type: "bytes", name: "data" },
        { type: "uint8", name: "operation" },
        { type: "uint256", name: "safeTxGas" },
        { type: "uint256", name: "baseGas" },
        { type: "uint256", name: "gasPrice" },
        { type: "address", name: "gasToken" },
        { type: "address", name: "refundReceiver" },
        { type: "uint256", name: "nonce" },
      ],
    },
    {
      to: call.to,
      value: call.value,
      data: call.data,
      operation,
      safeTxGas: 0n,
      baseGas: 0n,
      gasPrice: 0n,
      gasToken: ethers.ZeroAddress,
      refundReceiver: ethers.ZeroAddress,
      nonce,
    },
  );
  if (localHash !== safeTxHash) {
    throw new Error(
      `${label}: Safe ${safeAddress} reports safeTxHash ${safeTxHash}, locally computed ${localHash}; refusing to sign.`,
    );
  }
  const signatures = ethers.concat(
    signers.map((owner) => {
      const key = keys.get(owner);
      if (key === undefined) throw new Error(`no key for owner ${owner}`);
      return key.sign(safeTxHash).serialized;
    }),
  );

  log(
    `  ${label}: Safe ${safeAddress} nonce ${nonce}, safeTxHash ${safeTxHash}, signed by ${signers.join(", ")}.`,
  );
  if (dryRun) {
    const ok: boolean = await safe.execTransaction.staticCall(
      ...txArgs,
      signatures,
    );
    if (!ok) throw new Error(`${label}: dry run returned false.`);
    const gas: bigint = await safe.execTransaction.estimateGas(
      ...txArgs,
      signatures,
    );
    log(`  ${label}: DRY RUN ok, estimated gas ${gas}; nothing sent.`);
    return { safeTxHash, txHash: null, gasUsed: gas };
  }

  const estimate: bigint = await safe.execTransaction.estimateGas(
    ...txArgs,
    signatures,
  );
  const tx: ethers.ContractTransactionResponse = await safe.execTransaction(
    ...txArgs,
    signatures,
    { gasLimit: (estimate * 13n) / 10n },
  );
  const receipt = await tx.wait();
  if (receipt === null || receipt.status !== 1) {
    throw new Error(`${label}: execTransaction ${tx.hash} did not succeed.`);
  }
  const events = receipt.logs
    .filter((entry) => ethers.getAddress(entry.address) === safeAddress)
    .map((entry) => safe.interface.parseLog(entry))
    .filter((parsed) => parsed !== null);
  const success = events.some(
    (parsed) =>
      parsed.name === "ExecutionSuccess" && parsed.args.txHash === safeTxHash,
  );
  if (!success) {
    throw new Error(
      `${label}: execTransaction ${tx.hash} mined without ExecutionSuccess for ${safeTxHash}.`,
    );
  }
  log(`  ${label}: executed in tx ${tx.hash} (gas ${receipt.gasUsed}).`);
  return { safeTxHash, txHash: tx.hash, gasUsed: receipt.gasUsed };
}

export interface TimelockBatch {
  readonly calls: readonly SafeCall[];
  readonly predecessor: string;
  readonly salt: string;
}

export interface TimelockRun {
  readonly safe: string;
  readonly timelock: string;
  readonly batch: TimelockBatch;
  readonly keys: OwnerKeys;
  readonly submitter: ethers.Signer;
  readonly dryRun: boolean;
  /** When the Timelock has a delay: true polls until the batch is ready and executes it. */
  readonly waitForDelay: boolean;
  readonly label: string;
  readonly log: Log;
}

export type TimelockOutcome =
  | "executed"
  | "already-executed"
  | "scheduled"
  | "dry-run";

export interface TimelockResult {
  readonly operationId: string;
  readonly outcome: TimelockOutcome;
  readonly readyAt: bigint | null;
  readonly safeExecutions: readonly SafeExecutionResult[];
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Runs a batch through the Timelock from the Gov Safe. With a zero min delay, scheduleBatch and executeBatch go
 * out in ONE Safe transaction (DELEGATECALL into MultiSendCallOnly), so the batch cannot be left half done.
 * With a delay, the batch is scheduled, then executed once ready (or left scheduled when waitForDelay is false,
 * to be resumed by re-running with the same batch and salt). Re-running a finished batch is a no-op.
 */
export async function executeThroughTimelock(
  run: TimelockRun,
): Promise<TimelockResult> {
  const { batch, submitter, label, log } = run;
  if (batch.calls.length === 0) throw new Error(`${label}: empty batch.`);
  if (batch.calls.some((call) => call.value !== 0n)) {
    throw new Error(`${label}: batches carrying ETH are not supported.`);
  }
  const timelock = new ethers.Contract(run.timelock, TIMELOCK_ABI, submitter);
  const targets = batch.calls.map((call) => call.to);
  const values = batch.calls.map(() => 0n);
  const payloads = batch.calls.map((call) => call.data);
  const operationId: string = await timelock.hashOperationBatch(
    targets,
    values,
    payloads,
    batch.predecessor,
    batch.salt,
  );
  const minDelay: bigint = await timelock.getMinDelay();
  const state = async (): Promise<OperationState> =>
    Number(await timelock.getOperationState(operationId)) as OperationState;
  const scheduleCall: SafeCall = {
    to: run.timelock,
    value: 0n,
    data: timelock.interface.encodeFunctionData("scheduleBatch", [
      targets,
      values,
      payloads,
      batch.predecessor,
      batch.salt,
      minDelay,
    ]),
  };
  const executeCall: SafeCall = {
    to: run.timelock,
    value: 0n,
    data: timelock.interface.encodeFunctionData("executeBatch", [
      targets,
      values,
      payloads,
      batch.predecessor,
      batch.salt,
    ]),
  };
  const viaSafe = (
    call: SafeCall,
    operation: Operation,
    step: string,
  ): Promise<SafeExecutionResult> =>
    execSafeTransaction({
      safe: run.safe,
      call,
      operation,
      keys: run.keys,
      submitter,
      dryRun: run.dryRun,
      label: `${label} ${step}`,
      log,
    });

  log(
    `  ${label}: Timelock ${run.timelock} min delay ${minDelay}s, operation ${operationId}, ${batch.calls.length} call(s).`,
  );
  const executions: SafeExecutionResult[] = [];
  let current = await state();
  if (current === OperationState.Done) {
    log(`  ${label}: operation already executed; nothing to do.`);
    return {
      operationId,
      outcome: "already-executed",
      readyAt: null,
      safeExecutions: executions,
    };
  }
  if (current === OperationState.Unset && minDelay === 0n) {
    executions.push(
      await viaSafe(
        multiSendCallOnly([scheduleCall, executeCall]),
        Operation.DelegateCall,
        "schedule+execute",
      ),
    );
    if (run.dryRun) {
      return {
        operationId,
        outcome: "dry-run",
        readyAt: null,
        safeExecutions: executions,
      };
    }
    if ((await state()) !== OperationState.Done) {
      throw new Error(
        `${label}: operation ${operationId} is not Done after schedule+execute.`,
      );
    }
    return {
      operationId,
      outcome: "executed",
      readyAt: null,
      safeExecutions: executions,
    };
  }
  if (current === OperationState.Unset) {
    executions.push(await viaSafe(scheduleCall, Operation.Call, "schedule"));
    if (run.dryRun) {
      return {
        operationId,
        outcome: "dry-run",
        readyAt: null,
        safeExecutions: executions,
      };
    }
    current = await state();
  }
  const readyAt: bigint = await timelock.getTimestamp(operationId);
  const provider = submitter.provider;
  if (provider === null) throw new Error("submitter has no provider.");
  // A chain only stamps a new time when it mines, so an idle chain's latest block lags the wall clock: the
  // later of the two decides when the next block can execute the batch.
  const now = async (): Promise<bigint> => {
    const block = await provider.getBlock("latest");
    const chainNow = BigInt(block?.timestamp ?? 0);
    const wallNow = BigInt(Math.floor(Date.now() / 1000));
    return chainNow > wallNow ? chainNow : wallNow;
  };
  if (current === OperationState.Waiting && !run.waitForDelay) {
    log(
      `  ${label}: scheduled; ready at unix ${readyAt} (in ${readyAt - (await now())}s). Re-run with the same batch to execute.`,
    );
    return {
      operationId,
      outcome: "scheduled",
      readyAt,
      safeExecutions: executions,
    };
  }
  for (let t = await now(); t < readyAt; t = await now()) {
    const remaining = readyAt - t;
    log(`  ${label}: waiting ${remaining}s for the Timelock delay...`);
    await sleep(Number(remaining > 60n ? 60n : remaining) * 1000 + 1000);
  }
  let executed: SafeExecutionResult | null = null;
  for (let attempt = 1; executed === null; attempt++) {
    try {
      executed = await viaSafe(executeCall, Operation.Call, "execute");
    } catch (e) {
      // Only the first blocks after readyAt can still read as Waiting; anything else is a real failure.
      if (attempt >= 3 || (await state()) !== OperationState.Waiting) throw e;
      log(
        `  ${label}: not ready on-chain yet (attempt ${attempt}); retrying in 5s...`,
      );
      await sleep(5000);
    }
  }
  executions.push(executed);
  if (run.dryRun) {
    return {
      operationId,
      outcome: "dry-run",
      readyAt,
      safeExecutions: executions,
    };
  }
  if ((await state()) !== OperationState.Done) {
    throw new Error(
      `${label}: operation ${operationId} is not Done after execute.`,
    );
  }
  return {
    operationId,
    outcome: "executed",
    readyAt,
    safeExecutions: executions,
  };
}

/** Reads a JSON file as an object, naming the file in every error. */
export function readJsonObject(
  file: string,
  what: string,
): Record<string, unknown> {
  if (!fs.existsSync(file)) throw new Error(`${what} ${file} does not exist.`);
  let parsed: unknown;
  try {
    parsed = JSON.parse(fs.readFileSync(file, "utf8"));
  } catch (e) {
    const detail = e instanceof Error ? e.message : String(e);
    throw new Error(`${what} ${file} is not valid JSON: ${detail}`);
  }
  return asRecord(parsed, `${what} ${file}`);
}

export function requireEnv(name: string): string {
  const raw = process.env[name];
  if (raw === undefined || raw.trim() === "") {
    throw new Error(`${name} is not set.`);
  }
  return raw.trim();
}

export function envAddress(name: string, fallback: unknown): string {
  const raw = process.env[name];
  if (raw !== undefined && raw.trim() !== "")
    return checksummed(raw.trim(), name);
  if (fallback === null) throw new Error(`${name} is not set.`);
  if (fallback === undefined || fallback === "") {
    throw new Error(
      `${name} is not set and the deployment record has no value for it.`,
    );
  }
  return checksummed(fallback, `${name} (from the deployment record)`);
}

export function envFlag(name: string, fallback: boolean): boolean {
  const raw = process.env[name];
  if (raw === undefined || raw.trim() === "") return fallback;
  if (raw === "true") return true;
  if (raw === "false") return false;
  throw new Error(`${name} must be "true" or "false", got ${raw}.`);
}
