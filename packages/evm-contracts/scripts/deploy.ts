/**
 * Fresh pre-mainnet deployment of the DarkPool + NOX contract set under governance.
 *
 * All stateful contracts are UUPS proxies initialized atomically (impl + initialize in one tx).
 * Governance:
 *   - OZ TimelockController (TIMELOCK_MIN_DELAY_SECS, default 48h) holds DEFAULT_ADMIN + UPGRADER on every
 *     contract.
 *   - Governance Safe (3-of-5, out-of-band) is the sole proposer, executor and canceller on the
 *     Timelock. OZ grants CANCELLER to every proposer in the constructor, so the holder set is asserted
 *     exhaustively rather than probed address by address.
 *   - Guardian Safe (2-of-3, out-of-band) holds the DarkPool PAUSER role and NOT the Timelock CANCELLER
 *     role. The pauser must not be able to veto its own unpause; see the wiring note at Step 8.
 *   - The deploying EOA renounces all power before the script exits; every wiring assertion that can be
 *     evaluated beforehand runs in the preflight, so the renounce is the last irreversible act.
 *
 * Upgrade runbook: before any on-chain upgrade, run `validateUpgrade` against the DEPLOYED
 *   .openzeppelin/<network>.json manifest on the fork job. The in-repo DarkPoolV1 baseline anchors the
 *   CI gate but cannot see a MerkleTreeLib.Tree reshape (shared library); the deployed manifest anchors
 *   to real proxy storage and is the authoritative pre-upgrade storage-compat check.
 *
 * Required env:
 *   GOV_SAFE       governance multisig (3-of-5), Timelock proposer + executor + canceller
 *   GUARDIAN_SAFE  guardian multisig (2-of-3), DarkPool pauser, NoxRegistry slasher, NoxRewardPool
 *                  admin + distributor. Explicitly NOT a Timelock canceller.
 *   STAKING_TOKEN  ERC20 staking token. Required off local; a dev MockERC20 is deployed only on
 *                  hardhat/localhost, because it has an unpermissioned mint and NoxRegistry writes the
 *                  token once with no update path.
 * Optional env:
 *   COMPLIANCE_SECRET_KEY  reuse an existing compliance BJJ secret (else one is generated and written
 *                          to the sibling .secrets.json before any deploy transaction)
 *   LOCAL_TEST_COMPLIANCE_SECRET_KEY  deterministic fixture accepted only by hardhat/localhost
 *   SWAP_ROUTER            deploy UniswapAdaptor against this router
 *   FEE_ASSETS             comma-separated ERC20 addresses accepted for Nox execution fees; required off local
 *   TIMELOCK_MIN_DELAY_SECS    Timelock minimum delay in seconds (default 172800 = 48h)
 *   ADMIN_TRANSFER_DELAY_SECS  AccessControlDefaultAdminRules DEFAULT_ADMIN transfer delay in seconds on
 *                              DarkPool, NoxRegistry and NoxRewardPool (default 172800 = 48h)
 *                          Either may be 0, but a value below 48h is refused outside SHORT_DELAY_CHAIN_IDS.
 *   SKIP_EXPLORER_VERIFY   "true" skips block-explorer verification (forks and rehearsals)
 *   ALLOW_REDEPLOY         "true" deploys even though <network>-latest.json exists; refused otherwise off local
 *   DEPLOYMENTS_DIR        where the record, the latest pointer and the secrets land (default deployments/)
 *
 * Usage:
 *   GOV_SAFE=0x.. GUARDIAN_SAFE=0x.. npx hardhat run scripts/deploy.ts --network <net>
 */

import { config, ethers, network, upgrades, run } from "hardhat";
import * as fs from "fs";
import * as path from "path";
import * as crypto from "crypto";
import { Base8, mulPointEscalar, Point } from "@zk-kit/baby-jubjub";
import { Manifest } from "@openzeppelin/upgrades-core";
import type { BaseContract } from "ethers";

const BJJ_SUBGROUP_ORDER =
  2736030358979909402780800718157159386076813972158567259200215660948447373041n;

// Production default: a 48h timelock, and a 2-step DEFAULT_ADMIN transfer delay (AccessControlDefaultAdminRules)
// that matches it.
const DEFAULT_GOVERNANCE_DELAY = 48n * 60n * 60n;
const UINT48_MAX = 2n ** 48n - 1n;
// A delay below the production default is a testnet affordance: the in-process chain, Arbitrum Sepolia and
// Sepolia. Anywhere else it would hand governance an instant path around the review window.
const SHORT_DELAY_CHAIN_IDS: ReadonlySet<bigint> = new Set([
  31337n,
  421614n,
  11155111n,
]);

const MIN_STAKE = ethers.parseEther("1");
const UNSTAKE_DELAY = 86400n; // contract minimum (1 day)
const MIN_STAKE_FLOOR = ethers.parseEther("1");

// EIP-1967 storage slots.
const IMPL_SLOT =
  "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";
const ADMIN_SLOT =
  "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103";

const DEFAULT_ADMIN_ROLE = ethers.ZeroHash;

function requireSafeAddress(name: string): string {
  const raw = process.env[name];
  if (!raw) {
    throw new Error(`${name} is not set; supply the multisig address in env.`);
  }
  if (!ethers.isAddress(raw)) {
    throw new Error(`${name}=${raw} is not a valid address.`);
  }
  const addr = ethers.getAddress(raw);
  if (addr === ethers.ZeroAddress) {
    throw new Error(`${name} must be non-zero.`);
  }
  return addr;
}

function optionalAddress(name: string): string | null {
  const raw = process.env[name];
  if (raw === undefined || raw.trim() === "") return null;
  if (!ethers.isAddress(raw)) {
    throw new Error(`${name} is not a valid address: ${raw}`);
  }
  const address = ethers.getAddress(raw);
  if (address === ethers.ZeroAddress) {
    throw new Error(`${name} must be non-zero.`);
  }
  return address;
}

function configuredFeeAssets(isLocal: boolean): string[] | null {
  const raw = process.env.FEE_ASSETS;
  if (raw === undefined || raw.trim() === "") {
    if (!isLocal) {
      throw new Error(
        `FEE_ASSETS is required on network ${network.name}; supply the supported fee-token addresses explicitly.`,
      );
    }
    return null;
  }
  const assets = raw.split(",").map((asset) => {
    const candidate = asset.trim();
    if (!ethers.isAddress(candidate)) {
      throw new Error(
        `FEE_ASSETS contains an invalid ERC20 address: ${candidate}`,
      );
    }
    const address = ethers.getAddress(candidate);
    if (address === ethers.ZeroAddress) {
      throw new Error(
        `FEE_ASSETS contains an invalid ERC20 address: ${candidate}`,
      );
    }
    return address;
  });
  const seen = new Set<string>();
  for (const asset of assets) {
    const key = asset.toLowerCase();
    if (seen.has(key)) {
      throw new Error(
        `FEE_ASSETS contains a duplicate ERC20 address: ${asset}`,
      );
    }
    seen.add(key);
  }
  return assets;
}

function positiveUint256(name: string, fallback: string): bigint {
  let value: bigint;
  try {
    value = BigInt(process.env[name] ?? fallback);
  } catch {
    throw new Error(`${name} must be an unsigned decimal integer.`);
  }
  if (value <= 0n) throw new Error(`${name} must be positive.`);
  if (value > ethers.MaxUint256) {
    throw new Error(`${name} exceeds uint256.`);
  }
  return value;
}

function governanceDelay(name: string, max: bigint): bigint {
  const raw = process.env[name];
  if (raw === undefined || raw.trim() === "") return DEFAULT_GOVERNANCE_DELAY;
  if (!/^[0-9]+$/.test(raw.trim())) {
    throw new Error(
      `${name}=${raw} must be an unsigned decimal number of seconds.`,
    );
  }
  const value = BigInt(raw.trim());
  if (value > max) throw new Error(`${name}=${raw} exceeds ${max}.`);
  return value;
}

/** Reads TIMELOCK_MIN_DELAY_SECS and ADMIN_TRANSFER_DELAY_SECS, refusing a short delay off SHORT_DELAY_CHAIN_IDS. */
export function governanceDelays(chainId: bigint): {
  timelockMinDelay: bigint;
  adminTransferDelay: bigint;
} {
  const timelockMinDelay = governanceDelay(
    "TIMELOCK_MIN_DELAY_SECS",
    ethers.MaxUint256,
  );
  const adminTransferDelay = governanceDelay(
    "ADMIN_TRANSFER_DELAY_SECS",
    UINT48_MAX,
  );
  for (const [name, value] of [
    ["TIMELOCK_MIN_DELAY_SECS", timelockMinDelay],
    ["ADMIN_TRANSFER_DELAY_SECS", adminTransferDelay],
  ] as const) {
    if (
      value < DEFAULT_GOVERNANCE_DELAY &&
      !SHORT_DELAY_CHAIN_IDS.has(chainId)
    ) {
      throw new Error(
        `${name}=${value} is below the ${DEFAULT_GOVERNANCE_DELAY}s production default, which is accepted ` +
          `only on chain ids ${[...SHORT_DELAY_CHAIN_IDS].join(", ")} (this is ${chainId}).`,
      );
    }
  }
  return { timelockMinDelay, adminTransferDelay };
}

function generateComplianceKeypair(): { sk: bigint; pk: Point<bigint> } {
  for (;;) {
    const rawSk = BigInt("0x" + crypto.randomBytes(32).toString("hex"));
    const sk = rawSk % BJJ_SUBGROUP_ORDER;
    if (sk !== 0n) return { sk, pk: mulPointEscalar(Base8, sk) };
  }
}

async function deployVerifier(
  contractPath: string,
): Promise<{ verifier: string; name: string }> {
  const name =
    contractPath.split("/").pop()?.replace(".sol", "") || contractPath;
  const factory = await ethers.getContractFactory(
    `${contractPath}:HonkVerifier`,
  );
  const verifier = await factory.deploy();
  await verifier.waitForDeployment();
  const addr = await verifier.getAddress();
  console.log(`    ${name}: ${addr}`);
  return { verifier: addr, name };
}

// Circuit provenance is the point of the record, so a missing artifact is an abort off local rather
// than the string "NOT_FOUND" written into the file that is supposed to prove what was deployed.
function sha256File(filePath: string, required: boolean): string {
  if (!fs.existsSync(filePath)) {
    if (required) {
      throw new Error(
        `circuit artifact ${filePath} is missing; run nargo compile before deploying, or the ` +
          `deployment record cannot record what was deployed.`,
      );
    }
    return "NOT_FOUND";
  }
  return crypto
    .createHash("sha256")
    .update(fs.readFileSync(filePath))
    .digest("hex");
}

const VK_HASH_RE = /uint256 constant VK_HASH = (0x[0-9a-fA-F]{64});/;

// Read from the verifier source compiled and deployed in this run. The VK hash binds a deployed
// verifier to a specific circuit build, so a record without it cannot be checked against one.
function verifierVkHash(contractPath: string): string {
  const src = fs.readFileSync(path.join(__dirname, "..", contractPath), "utf8");
  const match = src.match(VK_HASH_RE);
  if (!match) {
    throw new Error(`no VK_HASH constant found in ${contractPath}`);
  }
  return match[1];
}

async function tryVerify(
  address: string,
  constructorArgs: unknown[],
  contract?: string,
): Promise<void> {
  if (network.name === "hardhat" || network.name === "localhost") return;
  try {
    await run("verify:verify", {
      address,
      constructorArguments: constructorArgs,
      contract,
    });
    console.log(`  Verified ${address}`);
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    console.log(`  Verify ${address}: ${msg}`);
  }
}

/**
 * The UUPS storage-layout manifest for THIS network, located by upgrades-core itself. It names the file from its
 * own chain table (`arbitrum-sepolia.json` for 421614, `unknown-<chainId>.json` for a chain it does not know) and
 * keeps an anvil or hardhat instance's manifest in the OS temp dir, so a name derived from the Hardhat network
 * name misses the file on every chain the table knows. The manifest must list every proxy this run deployed:
 * the record is what a future upgrade trusts as its storage-compat anchor, and a manifest without these proxies
 * belongs to some other deployment.
 *
 * Returns null only when the manifest is optional and does not list the proxies.
 */
async function readManifest(
  proxies: readonly string[],
  required: boolean,
): Promise<unknown> {
  const manifest = await Manifest.forNetwork(network.provider);
  const data = await manifest.read();
  const listed = new Set(
    data.proxies.map((proxy) => ethers.getAddress(proxy.address)),
  );
  const missing = proxies.filter(
    (proxy) => !listed.has(ethers.getAddress(proxy)),
  );
  if (missing.length === 0) return data;
  if (required) {
    throw new Error(
      `storage-layout manifest ${manifest.file} does not list the proxies deployed in this run ` +
        `(${missing.join(", ")}). The upgrade runbook treats it as the authoritative pre-upgrade compat ` +
        `anchor, so it must ride in the deployment record.`,
    );
  }
  return null;
}

async function slot(addr: string, s: string): Promise<string> {
  const raw = await ethers.provider.getStorage(addr, s);
  return ethers.getAddress("0x" + raw.slice(-40));
}

export interface RoleExpectation {
  readonly name: string;
  readonly role: string;
  readonly holders: readonly string[];
}

/**
 * Compares every current holder of every role on an AccessControl contract with `expected`. The candidates are
 * every account a RoleGranted event since `fromBlock` names, plus the expected holders and `probe`, each confirmed
 * with hasRole: a revoked grant drops out, a lagging log index cannot hide an expected holder, and a role missing
 * from `expected` must have no holder at all.
 */
export async function roleHolderProblems(
  label: string,
  contract: BaseContract,
  fromBlock: number,
  expected: readonly RoleExpectation[],
  probe: ReadonlyMap<string, string>,
): Promise<string[]> {
  const candidates = new Map<string, Set<string>>();
  const add = (role: string, account: string): void => {
    const accounts = candidates.get(role) ?? new Set<string>();
    accounts.add(ethers.getAddress(account));
    candidates.set(role, accounts);
  };
  for (const entry of expected) {
    for (const holder of entry.holders) add(entry.role, holder);
    for (const account of probe.keys()) add(entry.role, account);
  }
  for (const event of await contract.queryFilter(
    contract.getEvent("RoleGranted"),
    fromBlock,
  )) {
    if ("args" in event) {
      add(
        String(event.args.getValue("role")),
        String(event.args.getValue("account")),
      );
    }
  }
  const hasRole = contract.getFunction("hasRole");
  const describe = (accounts: ReadonlySet<string>): string =>
    `{${[...accounts].map((a) => probe.get(a) ?? a).join(", ") || "nobody"}}`;
  const problems: string[] = [];
  for (const [role, accounts] of candidates) {
    const entry = expected.find((e) => e.role === role);
    const want = new Set(
      (entry?.holders ?? []).map((a) => ethers.getAddress(a)),
    );
    const held = await Promise.all(
      [...accounts].map(
        async (account) =>
          [account, Boolean(await hasRole(role, account))] as const,
      ),
    );
    const holders = new Set(held.filter(([, has]) => has).map(([a]) => a));
    const same =
      holders.size === want.size && [...want].every((a) => holders.has(a));
    if (!same) {
      problems.push(
        `${label}.${entry?.name ?? `role ${role}`} is held by ${describe(holders)}, expected ${describe(want)}`,
      );
    }
  }
  return problems;
}

/** Retries a read-only step on a transient RPC error; a returned result, good or bad, is final. */
async function withRetries<T>(
  what: string,
  body: () => Promise<T>,
): Promise<T> {
  for (let attempt = 1; ; attempt++) {
    try {
      return await body();
    } catch (e) {
      if (attempt >= 3) throw e;
      const detail = e instanceof Error ? e.message : String(e);
      console.log(
        `  ${what} failed (attempt ${attempt}/3): ${detail}; retrying in 5s...`,
      );
      await new Promise((resolve) => setTimeout(resolve, 5000));
    }
  }
}

/**
 * Off local, a second run would deploy a separate contract set and repoint `<network>-latest.json`, which the
 * governance scripts and every downstream config read by default. Refused unless ALLOW_REDEPLOY=true.
 */
export function assertNoPriorDeployment(
  latestFile: string,
  isLocal: boolean,
): void {
  if (isLocal || !fs.existsSync(latestFile)) return;
  if (process.env.ALLOW_REDEPLOY === "true") {
    console.log(
      `  WARNING: ${latestFile} exists; ALLOW_REDEPLOY=true deploys a second contract set and repoints it.`,
    );
    return;
  }
  throw new Error(
    `${latestFile} already records a deployment on ${network.name}. Running again deploys a second, separate ` +
      "contract set and repoints the latest record at it. Set ALLOW_REDEPLOY=true to do that deliberately.",
  );
}

/** Narrowed to what a mis-wiring needs, so the test seams cannot be used to reach anything else. */
export interface MisWiringContext {
  readonly grantCanceller: (account: string) => Promise<void>;
  readonly grantTimelockRole: (role: string, account: string) => Promise<void>;
  readonly cancellerRole: string;
  readonly proposerRole: string;
  readonly executorRole: string;
  readonly govSafe: string;
  readonly guardianSafe: string;
  readonly deployer: string;
}

export interface DeployOptions {
  /**
   * Runs after governance wiring and before the preflight. It exists so a test can deliberately
   * mis-wire the topology and prove the preflight aborts AHEAD of the renounce, which is the property
   * the preflight exists for and which cannot be observed from the outside any other way.
   */
  readonly afterGovernanceWiring?: (context: MisWiringContext) => Promise<void>;
  /**
   * Runs after the preflight and before the renounce: the window in which the deployer key still administers
   * the Timelock. A test uses it to prove the post-renounce re-check catches a grant made in that window.
   */
  readonly beforeRenounce?: (context: MisWiringContext) => Promise<void>;
}

export interface DeployResult {
  readonly deployment: Record<string, unknown>;
  readonly deployFile: string;
  readonly secretsFile: string | null;
}

/**
 * The whole deployment, exported so it can be driven in-process by a test against the same chain the
 * test asserts on. Running it in a child process gives the child its own ephemeral chain, and the
 * addresses it reports then resolve to nothing.
 */
export async function deploy(
  options: DeployOptions = {},
): Promise<DeployResult> {
  const [deployer] = await ethers.getSigners();
  const chainId = (await ethers.provider.getNetwork()).chainId;
  const balance = await ethers.provider.getBalance(deployer.address);

  const isLocal = network.name === "hardhat" || network.name === "localhost";

  const { timelockMinDelay, adminTransferDelay } = governanceDelays(chainId);

  const govSafe = requireSafeAddress("GOV_SAFE");
  const guardianSafe = requireSafeAddress("GUARDIAN_SAFE");
  const stakingToken = optionalAddress("STAKING_TOKEN");
  const swapRouter = optionalAddress("SWAP_ROUTER");
  const explicitFeeAssets = configuredFeeAssets(isLocal);
  const committeeThreshold = positiveUint256("COMPLIANCE_THRESHOLD", "3");
  const committeeSize = positiveUint256("COMPLIANCE_COMMITTEE_SIZE", "5");
  if (committeeThreshold > committeeSize) {
    throw new Error(
      "COMPLIANCE_THRESHOLD must not exceed COMPLIANCE_COMMITTEE_SIZE.",
    );
  }
  const configuredSk = process.env.COMPLIANCE_SECRET_KEY;
  const localFixtureSk = process.env.LOCAL_TEST_COMPLIANCE_SECRET_KEY;
  if (configuredSk !== undefined && localFixtureSk !== undefined) {
    throw new Error(
      "Set only one of COMPLIANCE_SECRET_KEY or LOCAL_TEST_COMPLIANCE_SECRET_KEY.",
    );
  }
  if (localFixtureSk !== undefined && !isLocal) {
    throw new Error(
      "LOCAL_TEST_COMPLIANCE_SECRET_KEY is accepted only on hardhat or localhost.",
    );
  }
  const suppliedSk = configuredSk ?? localFixtureSk;
  const suppliedSkName =
    configuredSk === undefined
      ? "LOCAL_TEST_COMPLIANCE_SECRET_KEY"
      : "COMPLIANCE_SECRET_KEY";
  let compliance: { sk: bigint; pk: Point<bigint> };
  if (suppliedSk !== undefined) {
    let rawSk: bigint;
    try {
      rawSk = BigInt(suppliedSk);
    } catch {
      throw new Error(
        `${suppliedSkName} must be an unsigned decimal or hexadecimal integer.`,
      );
    }
    if (rawSk <= 0n) {
      throw new Error(`${suppliedSkName} must be positive.`);
    }
    const sk = rawSk % BJJ_SUBGROUP_ORDER;
    if (sk === 0n) {
      throw new Error(`${suppliedSkName} reduces to zero.`);
    }
    compliance = { sk, pk: mulPointEscalar(Base8, sk) };
  } else {
    compliance = generateComplianceKeypair();
  }
  // One address holding both roles collapses the separation the wiring assertions exist to enforce, and
  // every one of them would still pass.
  if (govSafe === guardianSafe) {
    throw new Error(
      `GOV_SAFE and GUARDIAN_SAFE are the same address (${govSafe}); the pauser must not also hold the veto.`,
    );
  }

  console.log("DarkPool + NOX governed deployment");
  console.log(`  Network:       ${network.name} (chainId: ${chainId})`);
  console.log(`  Deployer:      ${deployer.address}`);
  console.log(`  Balance:       ${ethers.formatEther(balance)} ETH`);
  console.log(`  Gov Safe:      ${govSafe}`);
  console.log(`  Guardian Safe: ${guardianSafe}`);
  console.log(`  Timelock min delay:    ${timelockMinDelay}s`);
  console.log(`  Admin transfer delay:  ${adminTransferDelay}s`);
  if (
    timelockMinDelay < DEFAULT_GOVERNANCE_DELAY ||
    adminTransferDelay < DEFAULT_GOVERNANCE_DELAY
  ) {
    console.log(
      `  WARNING: governance delay below the ${DEFAULT_GOVERNANCE_DELAY}s production default; queued ` +
        "actions get no review window.",
    );
  }
  for (const [label, addr] of [
    ["GOV_SAFE", govSafe],
    ["GUARDIAN_SAFE", guardianSafe],
  ] as const) {
    if ((await ethers.provider.getCode(addr)) === "0x") {
      // An EOA here is not a weaker multisig, it is no multisig. GOV_SAFE inherits PROPOSER, EXECUTOR
      // and CANCELLER, so a single key would own governance outright, and every Step 10 assertion still
      // passes because they only check that the DEPLOYER holds nothing.
      if (!isLocal) {
        throw new Error(
          `${label} ${addr} has no code on network ${network.name}; it must be a deployed multisig contract.`,
        );
      }
      console.log(
        `  WARNING: ${label} ${addr} has no code; accepted only on ${network.name}.`,
      );
    }
  }
  const dependencies = [
    ...(stakingToken === null
      ? []
      : ([["STAKING_TOKEN", stakingToken]] as const)),
    ...(swapRouter === null ? [] : ([["SWAP_ROUTER", swapRouter]] as const)),
    ...(explicitFeeAssets ?? []).map(
      (asset) => ["FEE_ASSETS entry", asset] as const,
    ),
  ];
  for (const [label, address] of dependencies) {
    if ((await ethers.provider.getCode(address)) === "0x") {
      throw new Error(
        `${label} ${address} has no deployed code on network ${network.name}.`,
      );
    }
  }
  console.log();

  const startBlock = await ethers.provider.getBlockNumber();
  const startTime = new Date().toISOString();

  const timestamp = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
  const deployDir =
    process.env.DEPLOYMENTS_DIR ?? path.join(__dirname, "../deployments");
  fs.mkdirSync(deployDir, { recursive: true });
  const deployFile = path.join(deployDir, `${network.name}-${timestamp}.json`);
  const latestFile = path.join(deployDir, `${network.name}-latest.json`);
  assertNoPriorDeployment(latestFile, isLocal);
  const secretsFile = path.join(
    deployDir,
    `${network.name}-${timestamp}.secrets.json`,
  );

  if (localFixtureSk !== undefined) {
    console.log("Step 0: Using deterministic local test compliance keypair.");
  } else if (configuredSk !== undefined) {
    console.log("Step 0: Reusing supplied compliance keypair.");
  } else {
    console.log("Step 0: Generated a fresh compliance keypair.");
  }

  // Written to disk BEFORE any transaction. A generated secret that exists only in memory is lost to
  // any throw after the first deploy, and by then the pool is deployed and bound to its public key, so
  // every note encrypted to it would be permanently undecryptable. The file is gitignored alongside the
  // record and is owner-read-only.
  if (suppliedSk === undefined) {
    fs.writeFileSync(
      secretsFile,
      JSON.stringify(
        {
          network: network.name,
          chainId: Number(chainId),
          createdAt: startTime,
          complianceSecretKey: compliance.sk.toString(),
          compliancePublicKeyX: compliance.pk[0].toString(),
          compliancePublicKeyY: compliance.pk[1].toString(),
        },
        null,
        2,
      ),
      { mode: 0o600 },
    );
    console.log(`  Compliance secret written to ${secretsFile}`);
  }
  console.log(`  Compliance PK: (${compliance.pk[0]}, ${compliance.pk[1]})`);
  console.log();

  // bb 5.0 --optimized verifiers are self-contained monolithic contracts (no externalized ZKTranscriptLib) and
  // fit EIP-170 on their own.
  // Order MUST match the circuit-id constants in DarkPool.sol (deposit=0 .. join_multisig=9). There is
  // no deposit_multisig verifier: deposit is unified and mints a MULTISIG note from a private witness.
  const verifierPaths = [
    "contracts/verifiers/DepositVerifier.sol",
    "contracts/verifiers/WithdrawVerifier.sol",
    "contracts/verifiers/TransferVerifier.sol",
    "contracts/verifiers/JoinVerifier.sol",
    "contracts/verifiers/SplitVerifier.sol",
    "contracts/verifiers/PublicClaimVerifier.sol",
    "contracts/verifiers/WithdrawMultisigVerifier.sol",
    "contracts/verifiers/TransferMultisigVerifier.sol",
    "contracts/verifiers/SplitMultisigVerifier.sol",
    "contracts/verifiers/JoinMultisigVerifier.sol",
    "contracts/verifiers/KageVerifier.sol",
  ];
  // Everything below reads the filesystem and can throw, so it runs BEFORE the first transaction. Doing
  // it at record-build time put a throw after the renounce, where an abort leaves live governed
  // contracts and no deployment record at all.
  const circuitsDir = path.join(__dirname, "../../circuits/target");
  const circuitHashes = Object.fromEntries(
    [
      "deposit",
      "withdraw",
      "transfer",
      "join",
      "split",
      "public_claim",
      "withdraw_multisig",
      "transfer_multisig",
      "split_multisig",
      "join_multisig",
      "swap_intent",
      "swap_settle",
    ].map((name) => [
      name,
      sha256File(path.join(circuitsDir, `${name}.json`), !isLocal),
    ]),
  );
  const vkHashes = Object.fromEntries(
    verifierPaths.map((contractPath) => [
      contractPath.split("/").pop()?.replace(".sol", "") ?? contractPath,
      verifierVkHash(contractPath),
    ]),
  );
  console.log(
    `  Circuit artifacts and VK hashes read: ${Object.keys(circuitHashes).length} circuits, ` +
      `${Object.keys(vkHashes).length} verifiers.`,
  );
  console.log();

  console.log("Step 1: Poseidon2 library...");
  const poseidon2 = await (
    await ethers.getContractFactory("Poseidon2")
  ).deploy();
  await poseidon2.waitForDeployment();
  const poseidon2Addr = await poseidon2.getAddress();
  console.log(`  Poseidon2: ${poseidon2Addr}`);
  console.log();

  console.log("Step 2: Circuit verifiers...");
  const verifiers: { verifier: string; name: string }[] = [];
  for (const p of verifierPaths) verifiers.push(await deployVerifier(p));
  console.log();

  console.log("Step 3: Staking token...");
  let stakingTokenAddr: string;
  if (stakingToken !== null) {
    stakingTokenAddr = stakingToken;
    console.log(`  Using supplied staking token: ${stakingTokenAddr}`);
  } else {
    // MockERC20 has an unpermissioned public mint, and NoxRegistry writes the staking token only in
    // initialize with no setter, so falling back to it off local permanently binds stake economics to a
    // token anyone can print. Fail closed rather than deploy one.
    if (!isLocal) {
      throw new Error(
        `STAKING_TOKEN is required on network ${network.name}: the MockERC20 fallback has an open mint ` +
          `and NoxRegistry cannot be repointed after initialize.`,
      );
    }
    const token = await (
      await ethers.getContractFactory("MockERC20")
    ).deploy("NOX Stake Token", "NOX-STK", 18);
    await token.waitForDeployment();
    stakingTokenAddr = await token.getAddress();
    console.log(`  Deployed dev MockERC20 staking token: ${stakingTokenAddr}`);
  }
  console.log();

  console.log(`Step 4: TimelockController (min delay ${timelockMinDelay}s)...`);
  const timelock = await (
    await ethers.getContractFactory("TimelockController")
  ).deploy(timelockMinDelay, [govSafe], [govSafe], deployer.address);
  await timelock.waitForDeployment();
  const timelockAddr = await timelock.getAddress();
  // The scan floor for the CANCELLER holder-set check. The timelock is deployed here, so this block is
  // at or below its first RoleGranted event and the scan is complete by construction.
  const timelockDeployBlock =
    (await timelock.deploymentTransaction()?.wait())?.blockNumber ?? startBlock;
  console.log(`  TimelockController: ${timelockAddr}`);
  console.log();

  console.log("Step 5: NoxRegistry proxy...");
  const NoxRegistryFactory = await ethers.getContractFactory("NoxRegistry");
  const noxRegistry = await upgrades.deployProxy(
    NoxRegistryFactory,
    [
      [
        adminTransferDelay,
        timelockAddr,
        stakingTokenAddr,
        MIN_STAKE,
        UNSTAKE_DELAY,
        MIN_STAKE_FLOOR,
        guardianSafe, // slasher
        timelockAddr, // configManager
        timelockAddr, // upgrader
      ],
    ],
    { kind: "uups" },
  );
  await noxRegistry.waitForDeployment();
  const noxRegistryAddr = await noxRegistry.getAddress();
  console.log(`  NoxRegistry: ${noxRegistryAddr}`);
  console.log();

  console.log("Step 6: NoxRewardPool proxy...");
  const RewardPoolFactory = await ethers.getContractFactory("NoxRewardPool");
  const rewardPool = await upgrades.deployProxy(
    RewardPoolFactory,
    [
      [
        adminTransferDelay,
        timelockAddr,
        noxRegistryAddr,
        deployer.address, // temporary admin for atomic EntryPoint and asset wiring
        guardianSafe, // distributor (governance can reassign)
        timelockAddr, // upgrader
      ],
    ],
    { kind: "uups" },
  );
  await rewardPool.waitForDeployment();
  const rewardPoolAddr = await rewardPool.getAddress();
  console.log(`  NoxRewardPool: ${rewardPoolAddr}`);
  console.log();

  console.log("Step 7: DarkPool proxy (atomic)...");
  const DarkPoolFactory = await ethers.getContractFactory("DarkPool", {
    libraries: { Poseidon2: poseidon2Addr },
  });
  const darkPool = await upgrades.deployProxy(
    DarkPoolFactory,
    [
      [
        verifiers[0].verifier,
        verifiers[1].verifier,
        verifiers[2].verifier,
        verifiers[3].verifier,
        verifiers[4].verifier,
        verifiers[5].verifier,
        verifiers[6].verifier,
        verifiers[7].verifier,
        verifiers[8].verifier,
        verifiers[9].verifier,
        verifiers[10].verifier,
        compliance.pk[0],
        compliance.pk[1],
        adminTransferDelay,
        timelockAddr, // initialAdmin
        guardianSafe, // pauser
        timelockAddr, // upgrader
      ],
    ],
    { kind: "uups", unsafeAllow: ["external-library-linking"] },
  );
  await darkPool.waitForDeployment();
  const darkPoolAddr = await darkPool.getAddress();
  console.log(`  DarkPool: ${darkPoolAddr}`);
  console.log();

  console.log("Step 7a: Nox paid execution contracts...");
  const sandboxImplementation = await (
    await ethers.getContractFactory("NoxExecutionSandbox")
  ).deploy();
  await sandboxImplementation.waitForDeployment();
  const sandboxImplementationAddr = await sandboxImplementation.getAddress();

  const noxEntryPoint = await (
    await ethers.getContractFactory("NoxEntryPoint")
  ).deploy(rewardPoolAddr, sandboxImplementationAddr);
  await noxEntryPoint.waitForDeployment();
  const noxEntryPointAddr = await noxEntryPoint.getAddress();

  const howlPaymentAdapter = await (
    await ethers.getContractFactory("HowlPaymentAdapter")
  ).deploy(darkPoolAddr, noxEntryPointAddr);
  await howlPaymentAdapter.waitForDeployment();
  const howlPaymentAdapterAddr = await howlPaymentAdapter.getAddress();

  const bundleExecutor = await (
    await ethers.getContractFactory("BundleExecutor")
  ).deploy(darkPoolAddr);
  await bundleExecutor.waitForDeployment();
  const bundleExecutorAddr = await bundleExecutor.getAddress();

  const feeAssets = explicitFeeAssets ?? [stakingTokenAddr];
  for (const asset of feeAssets) {
    await (await rewardPool.setAssetStatus(asset, true)).wait();
    await (await rewardPool.classifyAsset(asset)).wait();
  }
  const ENTRYPOINT_ROLE = await rewardPool.ENTRYPOINT_ROLE();
  const POOL_ADMIN_ROLE = await rewardPool.ADMIN_ROLE();
  await (await rewardPool.grantRole(ENTRYPOINT_ROLE, noxEntryPointAddr)).wait();
  await (await rewardPool.transferOperationalAdmin(guardianSafe)).wait();

  console.log(
    `  NoxExecutionSandbox implementation: ${sandboxImplementationAddr}`,
  );
  console.log(`  NoxEntryPoint: ${noxEntryPointAddr}`);
  console.log(`  HowlPaymentAdapter: ${howlPaymentAdapterAddr}`);
  console.log(`  BundleExecutor: ${bundleExecutorAddr}`);
  console.log(`  Classified fee assets: ${feeAssets.join(", ")}`);
  console.log();

  console.log("Step 7b: ComplianceRegistry (social audit log)...");
  const complianceRegistry = await (
    await ethers.getContractFactory("ComplianceRegistry")
  ).deploy(timelockAddr, committeeThreshold, committeeSize);
  await complianceRegistry.waitForDeployment();
  const complianceRegistryAddr = await complianceRegistry.getAddress();
  console.log(
    `  ComplianceRegistry: ${complianceRegistryAddr} (t=${committeeThreshold}, n=${committeeSize}, admin=${timelockAddr})`,
  );
  console.log();

  const recordedCoreContracts = {
    poseidon2: poseidon2Addr,
    depositVerifier: verifiers[0].verifier,
    withdrawVerifier: verifiers[1].verifier,
    transferVerifier: verifiers[2].verifier,
    joinVerifier: verifiers[3].verifier,
    splitVerifier: verifiers[4].verifier,
    publicClaimVerifier: verifiers[5].verifier,
    withdrawMultisigVerifier: verifiers[6].verifier,
    transferMultisigVerifier: verifiers[7].verifier,
    splitMultisigVerifier: verifiers[8].verifier,
    joinMultisigVerifier: verifiers[9].verifier,
    kageVerifier: verifiers[10].verifier,
    complianceRegistry: complianceRegistryAddr,
    noxRegistry: noxRegistryAddr,
    noxRewardPool: rewardPoolAddr,
    noxSandboxImplementation: sandboxImplementationAddr,
    noxEntryPoint: noxEntryPointAddr,
    howlPaymentAdapter: howlPaymentAdapterAddr,
    bundleExecutor: bundleExecutorAddr,
    darkPool: darkPoolAddr,
    stakingToken: stakingTokenAddr,
  };
  const coreContractCodeHashes = Object.fromEntries(
    await Promise.all(
      Object.entries(recordedCoreContracts).map(async ([name, address]) => {
        const code = await ethers.provider.getCode(address);
        if (code === "0x") {
          throw new Error(
            `${name} has no deployed code before governance preflight`,
          );
        }
        return [name, ethers.keccak256(code)];
      }),
    ),
  );
  const proxySlots: Record<string, { impl: string; admin: string }> = {};
  const proxyImplementationCodeHashes: Record<string, string> = {};
  for (const [name, address] of [
    ["darkPool", darkPoolAddr],
    ["noxRegistry", noxRegistryAddr],
    ["noxRewardPool", rewardPoolAddr],
  ] as const) {
    const implementation = await slot(address, IMPL_SLOT);
    const admin = await slot(address, ADMIN_SLOT);
    const implementationCode = await ethers.provider.getCode(implementation);
    if (implementationCode === "0x") {
      throw new Error(
        `${name} implementation has no code before governance preflight`,
      );
    }
    proxySlots[name] = { impl: implementation, admin };
    proxyImplementationCodeHashes[name] = ethers.keccak256(implementationCode);
  }

  console.log("Step 8: Governance wiring...");
  // CANCELLER must NOT go to the DarkPool PAUSER holder. OZ TimelockController is its own DEFAULT_ADMIN
  // (TimelockController.sol:117), so revoking a canceller must itself be scheduled through the timelock, where
  // that same canceller can cancel the revocation. An entity holding both PAUSER and CANCELLER can therefore
  // pause the pool and cancel every unpause forever, with no on-chain recovery: a permanent freeze of all
  // pooled value by a 2-of-3 minority. The roles are split so the guardian keeps the fast emergency stop while
  // only govSafe can veto queued operations. Enforced structurally by the assertion in the verification step.
  const CANCELLER_ROLE = await timelock.CANCELLER_ROLE();
  await (await timelock.grantRole(CANCELLER_ROLE, govSafe)).wait();
  console.log(`  Granted Timelock CANCELLER_ROLE to govSafe ${govSafe}`);
  // DarkPool PAUSER was granted to the guardian in initialize (deployer cannot grant it post-init).
  console.log();

  const PROPOSER_ROLE = await timelock.PROPOSER_ROLE();
  const EXECUTOR_ROLE = await timelock.EXECUTOR_ROLE();
  const misWiring: MisWiringContext = {
    grantCanceller: async (account: string) => {
      await (await timelock.grantRole(CANCELLER_ROLE, account)).wait();
    },
    grantTimelockRole: async (role: string, account: string) => {
      await (await timelock.grantRole(role, account)).wait();
    },
    cancellerRole: CANCELLER_ROLE,
    proposerRole: PROPOSER_ROLE,
    executorRole: EXECUTOR_ROLE,
    govSafe,
    guardianSafe,
    deployer: deployer.address,
  };
  if (options.afterGovernanceWiring !== undefined) {
    await options.afterGovernanceWiring(misWiring);
  }

  console.log("Step 9: Preflight, before the point of no return...");
  // Everything here is a pure predicate over state that Step 8 has already fixed, so it is checked
  // BEFORE the renounce. Validating after the deployer has given up DEFAULT_ADMIN leaves a failure that
  // cannot be repaired: the roles are wrong and nobody outside the Timelock can still change them.
  const PAUSER_ROLE = await darkPool.PAUSER_ROLE();
  const DP_UPGRADER = await darkPool.UPGRADER_ROLE();
  const REG_UPGRADER = await noxRegistry.UPGRADER_ROLE();
  const POOL_UPGRADER = await rewardPool.UPGRADER_ROLE();

  // The complete CANCELLER holder set, read from the log rather than probed address by address. The
  // Timelock was deployed in this run, so scanning from its deploy block sees every grant that exists,
  // including the constructor's automatic grant to each proposer.
  const cancellerHolders = new Set<string>();
  for (const ev of await timelock.queryFilter(
    timelock.filters.RoleGranted(CANCELLER_ROLE),
    timelockDeployBlock,
  )) {
    cancellerHolders.add(ethers.getAddress(ev.args.account));
  }
  for (const ev of await timelock.queryFilter(
    timelock.filters.RoleRevoked(CANCELLER_ROLE),
    timelockDeployBlock,
  )) {
    cancellerHolders.delete(ethers.getAddress(ev.args.account));
  }

  const deployerMustNotHoldYet: {
    label: string;
    has: () => Promise<boolean>;
  }[] = [
    {
      label: "DarkPool.DEFAULT_ADMIN",
      has: () => darkPool.hasRole(DEFAULT_ADMIN_ROLE, deployer.address),
    },
    {
      label: "DarkPool.UPGRADER",
      has: () => darkPool.hasRole(DP_UPGRADER, deployer.address),
    },
    {
      label: "DarkPool.PAUSER",
      has: () => darkPool.hasRole(PAUSER_ROLE, deployer.address),
    },
    {
      label: "NoxRegistry.DEFAULT_ADMIN",
      has: () => noxRegistry.hasRole(DEFAULT_ADMIN_ROLE, deployer.address),
    },
    {
      label: "NoxRegistry.UPGRADER",
      has: () => noxRegistry.hasRole(REG_UPGRADER, deployer.address),
    },
    {
      label: "NoxRewardPool.DEFAULT_ADMIN",
      has: () => rewardPool.hasRole(DEFAULT_ADMIN_ROLE, deployer.address),
    },
    {
      label: "NoxRewardPool.UPGRADER",
      has: () => rewardPool.hasRole(POOL_UPGRADER, deployer.address),
    },
    {
      label: "NoxRewardPool.ADMIN",
      has: () => rewardPool.hasRole(POOL_ADMIN_ROLE, deployer.address),
    },
    {
      label: "Timelock.PROPOSER",
      has: () => timelock.hasRole(PROPOSER_ROLE, deployer.address),
    },
    {
      label: "Timelock.EXECUTOR",
      has: () => timelock.hasRole(EXECUTOR_ROLE, deployer.address),
    },
    {
      label: "Timelock.CANCELLER",
      has: () => timelock.hasRole(CANCELLER_ROLE, deployer.address),
    },
  ];
  for (const check of deployerMustNotHoldYet) {
    if (await check.has()) {
      throw new Error(
        `SECURITY: deployer EOA holds ${check.label}; aborting before the renounce.`,
      );
    }
  }

  const wiring: { label: string; ok: boolean }[] = [
    {
      label: "Timelock is DarkPool DEFAULT_ADMIN",
      ok: await darkPool.hasRole(DEFAULT_ADMIN_ROLE, timelockAddr),
    },
    {
      label: "Timelock is DarkPool UPGRADER",
      ok: await darkPool.hasRole(DP_UPGRADER, timelockAddr),
    },
    {
      label: "Guardian is DarkPool PAUSER",
      ok: await darkPool.hasRole(PAUSER_ROLE, guardianSafe),
    },
    // The separation that prevents a permanent freeze. If one entity ever holds both, it can pause and then
    // cancel every unpause, and the revocation of its own CANCELLER is equally cancellable.
    {
      label:
        "DarkPool PAUSER does NOT hold Timelock CANCELLER (no freeze deadlock)",
      ok: !(await timelock.hasRole(CANCELLER_ROLE, guardianSafe)),
    },
    {
      label: "Timelock is NoxRegistry DEFAULT_ADMIN",
      ok: await noxRegistry.hasRole(DEFAULT_ADMIN_ROLE, timelockAddr),
    },
    {
      label: "Timelock is NoxRewardPool DEFAULT_ADMIN",
      ok: await rewardPool.hasRole(DEFAULT_ADMIN_ROLE, timelockAddr),
    },
    {
      label: "Guardian is NoxRewardPool ADMIN",
      ok: await rewardPool.hasRole(POOL_ADMIN_ROLE, guardianSafe),
    },
    {
      label: "NoxEntryPoint holds RewardPool ENTRYPOINT_ROLE",
      ok: await rewardPool.hasRole(ENTRYPOINT_ROLE, noxEntryPointAddr),
    },
    {
      label: "NoxEntryPoint is linked to NoxRewardPool",
      ok: (await noxEntryPoint.REWARD_POOL()) === rewardPoolAddr,
    },
    {
      label: "NoxEntryPoint is linked to its sandbox implementation",
      ok:
        (await noxEntryPoint.SANDBOX_IMPLEMENTATION()) ===
        sandboxImplementationAddr,
    },
    {
      label: "HowlPaymentAdapter is linked to DarkPool and NoxEntryPoint",
      ok:
        (await howlPaymentAdapter.DARK_POOL()) === darkPoolAddr &&
        (await howlPaymentAdapter.ENTRY_POINT()) === noxEntryPointAddr,
    },
    {
      label: "BundleExecutor is linked to DarkPool",
      ok: (await bundleExecutor.DARK_POOL()) === darkPoolAddr,
    },
    {
      label: "Every configured Nox fee asset is supported and classified",
      ok: (
        await Promise.all(
          feeAssets.map(async (asset) =>
            Boolean(
              (await rewardPool.isSupportedAsset(asset)) &&
              (await rewardPool.isAssetClassified(asset)),
            ),
          ),
        )
      ).every(Boolean),
    },
    {
      label: "Gov Safe is Timelock PROPOSER",
      ok: await timelock.hasRole(PROPOSER_ROLE, govSafe),
    },
    {
      label: "Gov Safe is Timelock EXECUTOR",
      ok: await timelock.hasRole(EXECUTOR_ROLE, govSafe),
    },
    // The veto set, pinned positively and exhaustively. A negative check alone would still pass if a
    // third party held CANCELLER, and OZ grants it automatically to every proposer.
    {
      label: "Gov Safe is Timelock CANCELLER",
      ok: await timelock.hasRole(CANCELLER_ROLE, govSafe),
    },
    {
      label: `Timelock CANCELLER holder set is exactly {govSafe} (found ${[...cancellerHolders].join(", ") || "none"})`,
      ok: cancellerHolders.size === 1 && cancellerHolders.has(govSafe),
    },
    {
      label: "Timelock self-administers",
      ok: await timelock.hasRole(DEFAULT_ADMIN_ROLE, timelockAddr),
    },
    {
      label: `Timelock min delay is ${timelockMinDelay}s`,
      ok: (await timelock.getMinDelay()) === timelockMinDelay,
    },
    {
      label: `DEFAULT_ADMIN transfer delay is ${adminTransferDelay}s on DarkPool, NoxRegistry and NoxRewardPool`,
      ok: (
        await Promise.all(
          [darkPool, noxRegistry, rewardPool].map(
            async (contract) =>
              (await contract.defaultAdminDelay()) === adminTransferDelay,
          ),
        )
      ).every(Boolean),
    },
  ];
  for (const w of wiring) {
    console.log(`  [${w.ok ? "ok" : "FAIL"}] ${w.label}`);
    if (!w.ok) throw new Error(`SECURITY: wiring check failed: ${w.label}`);
  }

  // The wiring checks pin named holders. The deployer key administers the Timelock until the renounce, so it
  // could grant any Timelock role, or run an operation, for anyone; with a zero delay that operation lands at
  // once. This pins every holder of every role on every governed contract, the Timelock's operation log and
  // the proxy implementations, before the renounce and again after it.
  const integrityProbe = new Map<string, string>([
    [deployer.address, "deployer"],
    [timelockAddr, "timelock"],
    [govSafe, "govSafe"],
    [guardianSafe, "guardianSafe"],
    [noxEntryPointAddr, "noxEntryPoint"],
  ]);
  const roleTables = [
    {
      label: "DarkPool",
      contract: darkPool,
      roles: [
        { name: "PAUSER_ROLE", role: PAUSER_ROLE, holders: [guardianSafe] },
        { name: "UPGRADER_ROLE", role: DP_UPGRADER, holders: [timelockAddr] },
      ],
    },
    {
      label: "NoxRegistry",
      contract: noxRegistry,
      roles: [
        {
          name: "CONFIG_ROLE",
          role: await noxRegistry.CONFIG_ROLE(),
          holders: [timelockAddr],
        },
        {
          name: "SLASHER_ROLE",
          role: await noxRegistry.SLASHER_ROLE(),
          holders: [guardianSafe],
        },
        { name: "UPGRADER_ROLE", role: REG_UPGRADER, holders: [timelockAddr] },
      ],
    },
    {
      label: "NoxRewardPool",
      contract: rewardPool,
      roles: [
        { name: "ADMIN_ROLE", role: POOL_ADMIN_ROLE, holders: [guardianSafe] },
        {
          name: "DISTRIBUTOR_ROLE",
          role: await rewardPool.DISTRIBUTOR_ROLE(),
          holders: [guardianSafe],
        },
        {
          name: "ENTRYPOINT_ROLE",
          role: ENTRYPOINT_ROLE,
          holders: [noxEntryPointAddr],
        },
        {
          name: "UPGRADER_ROLE",
          role: POOL_UPGRADER,
          holders: [timelockAddr],
        },
      ],
    },
    {
      label: "ComplianceRegistry",
      contract: complianceRegistry,
      roles: [
        {
          name: "COMMITTEE_ADMIN_ROLE",
          role: await complianceRegistry.COMMITTEE_ADMIN_ROLE(),
          holders: [timelockAddr],
        },
        {
          name: "MEMBER_ROLE",
          role: await complianceRegistry.MEMBER_ROLE(),
          holders: [],
        },
      ],
    },
  ];
  const governanceIntegrity = async (
    timelockAdmins: readonly string[],
  ): Promise<string[]> => {
    const problems = await roleHolderProblems(
      "Timelock",
      timelock,
      startBlock,
      [
        {
          name: "DEFAULT_ADMIN_ROLE",
          role: DEFAULT_ADMIN_ROLE,
          holders: timelockAdmins,
        },
        { name: "PROPOSER_ROLE", role: PROPOSER_ROLE, holders: [govSafe] },
        { name: "EXECUTOR_ROLE", role: EXECUTOR_ROLE, holders: [govSafe] },
        { name: "CANCELLER_ROLE", role: CANCELLER_ROLE, holders: [govSafe] },
      ],
      integrityProbe,
    );
    for (const table of roleTables) {
      problems.push(
        ...(await roleHolderProblems(
          table.label,
          table.contract,
          startBlock,
          [
            {
              name: "DEFAULT_ADMIN_ROLE",
              role: DEFAULT_ADMIN_ROLE,
              holders: [timelockAddr],
            },
            ...table.roles,
          ],
          integrityProbe,
        )),
      );
    }
    const operations =
      (
        await timelock.queryFilter(
          timelock.filters.CallScheduled(),
          timelockDeployBlock,
        )
      ).length +
      (
        await timelock.queryFilter(
          timelock.filters.CallExecuted(),
          timelockDeployBlock,
        )
      ).length;
    if (operations > 0) {
      problems.push(
        `Timelock ${timelockAddr} logged ${operations} scheduled or executed call(s); a fresh deployment has none`,
      );
    }
    for (const [name, address] of [
      ["darkPool", darkPoolAddr],
      ["noxRegistry", noxRegistryAddr],
      ["noxRewardPool", rewardPoolAddr],
    ] as const) {
      const implementation = await slot(address, IMPL_SLOT);
      if (implementation !== proxySlots[name].impl) {
        problems.push(
          `${name} implementation is ${implementation}, deployed ${proxySlots[name].impl}`,
        );
      }
    }
    return problems;
  };
  const integrityScope =
    "Timelock, DarkPool, NoxRegistry, NoxRewardPool and ComplianceRegistry";
  const preflightProblems = await withRetries(
    "governance integrity check",
    () => governanceIntegrity([timelockAddr, deployer.address]),
  );
  for (const problem of preflightProblems) console.log(`  [FAIL] ${problem}`);
  if (preflightProblems.length > 0) {
    throw new Error(
      `SECURITY: governance integrity check failed: ${preflightProblems.join("; ")}`,
    );
  }
  console.log(
    `  [ok] Every role on ${integrityScope} is held by exactly its intended holders`,
  );
  console.log(
    "  [ok] Timelock has no scheduled or executed operation; proxy implementations are unchanged",
  );
  // Read here, before the renounce, so a missing or malformed manifest aborts while the deployer can
  // still fix the topology rather than after it has given up admin.
  const openzeppelinManifest = await readManifest(
    [darkPoolAddr, noxRegistryAddr, rewardPoolAddr],
    !isLocal,
  );
  console.log(
    `  Storage-layout manifest: ${openzeppelinManifest === null ? "none (optional on this network)" : "captured"}`,
  );
  console.log("  Governance topology verified; proceeding to renounce.");
  let adaptorAddr = "";
  let adaptorCodeHash = "";
  let postRenounceVerified = false;
  // Everything after the renounce is past the point where a re-run is safe, so the addresses are on disk
  // first. Only the timestamped record: the latest pointer the governance scripts read waits for the
  // post-renounce re-check.
  await writeRecord(false);
  console.log(`  Pre-renounce snapshot: ${deployFile}`);
  console.log();

  if (options.beforeRenounce !== undefined) {
    await options.beforeRenounce(misWiring);
  }

  console.log("Step 9b: Renouncing deployer's Timelock admin...");
  await (
    await timelock.renounceRole(DEFAULT_ADMIN_ROLE, deployer.address)
  ).wait();
  console.log("  Deployer renounced Timelock DEFAULT_ADMIN.");
  console.log();

  console.log("Step 10: Asserting the renounce landed...");

  // Only the Timelock admin is renounce-dependent. Every other holding was decided before the preflight
  // and is checked there, so the sole post-renounce assertion is that the renounce itself took effect.
  if (await timelock.hasRole(DEFAULT_ADMIN_ROLE, deployer.address)) {
    throw new Error(
      "SECURITY: deployer EOA still holds Timelock.DEFAULT_ADMIN after renouncing; aborting.",
    );
  }
  // Re-run over the window between the preflight and the renounce, in which the deployer key could still act.
  const postRenounceProblems = await withRetries(
    "post-renounce integrity check",
    () => governanceIntegrity([timelockAddr]),
  );
  for (const problem of postRenounceProblems) {
    console.log(`  [FAIL] ${problem}`);
  }
  if (postRenounceProblems.length > 0) {
    throw new Error(
      `SECURITY: after the renounce, ${postRenounceProblems.join("; ")}. Do not use this deployment; ` +
        "redeploy from a fresh deployer key.",
    );
  }
  console.log(
    `  [ok] Every role on ${integrityScope} is still held by exactly its intended holders`,
  );
  postRenounceVerified = true;

  console.log("  No EOA holds any privileged role.");
  console.log();

  console.log("Step 11: EIP-1967 proxy slots...");
  for (const [name, slots] of Object.entries(proxySlots)) {
    console.log(
      `  ${name}: impl=${slots.impl} admin=${slots.admin} (UUPS admin slot is 0)`,
    );
  }
  console.log();

  // The adaptor is optional and its deploy can revert on a bad router. Persist everything known so far
  // first, so a failure here costs the adaptor rather than the whole record.
  await writeRecord(true);
  if (swapRouter !== null) {
    console.log("Step 12: UniswapAdaptor...");
    const adaptor = await (
      await ethers.getContractFactory("UniswapAdaptor", {
        libraries: { Poseidon2: poseidon2Addr },
      })
    ).deploy(darkPoolAddr, swapRouter);
    await adaptor.waitForDeployment();
    adaptorAddr = await adaptor.getAddress();
    adaptorCodeHash = ethers.keccak256(
      await ethers.provider.getCode(adaptorAddr),
    );
    console.log(`  UniswapAdaptor: ${adaptorAddr}`);
    console.log();
  }

  if (!isLocal && process.env.SKIP_EXPLORER_VERIFY !== "true") {
    console.log("Step 13: Block-explorer verification (best-effort)...");
    await tryVerify(poseidon2Addr, []);
    for (let i = 0; i < verifiers.length; i++) {
      await tryVerify(
        verifiers[i].verifier,
        [],
        `${verifierPaths[i]}:HonkVerifier`,
      );
    }
    await tryVerify(timelockAddr, [
      timelockMinDelay.toString(),
      [govSafe],
      [govSafe],
      deployer.address,
    ]);
    await tryVerify(sandboxImplementationAddr, []);
    await tryVerify(noxEntryPointAddr, [
      rewardPoolAddr,
      sandboxImplementationAddr,
    ]);
    await tryVerify(howlPaymentAdapterAddr, [darkPoolAddr, noxEntryPointAddr]);
    await tryVerify(bundleExecutorAddr, [darkPoolAddr]);
    console.log();
  }

  // Built on demand so it can be written more than once: everything deployed so far is persisted before
  // the optional adaptor step, then refreshed after it. A record that only exists at the very end is a
  // record that a late failure destroys.
  function buildRecord(endBlock: number): Record<string, unknown> {
    const deployedContracts = {
      ...recordedCoreContracts,
      uniswapAdaptor: adaptorAddr,
    };
    const contractCodeHashes = {
      ...coreContractCodeHashes,
      ...(adaptorCodeHash === "" ? {} : { uniswapAdaptor: adaptorCodeHash }),
    };
    return {
      meta: {
        network: network.name,
        chainId: Number(chainId),
        deployer: deployer.address,
        deployedAt: startTime,
        startBlock,
        endBlock,
        postRenounceVerified,
      },
      governance: {
        timelock: timelockAddr,
        timelockMinDelaySeconds: Number(timelockMinDelay),
        adminTransferDelaySeconds: Number(adminTransferDelay),
        govSafe,
        guardianSafe,
      },
      compliance: {
        publicKeyX: compliance.pk[0].toString(),
        publicKeyY: compliance.pk[1].toString(),
      },
      contracts: deployedContracts,
      constructorArgs: {
        noxSandboxImplementation: [],
        noxEntryPoint: [rewardPoolAddr, sandboxImplementationAddr],
        howlPaymentAdapter: [darkPoolAddr, noxEntryPointAddr],
        bundleExecutor: [darkPoolAddr],
        complianceRegistry: [
          timelockAddr,
          committeeThreshold.toString(),
          committeeSize.toString(),
        ],
      },
      contractCodeHashes,
      proxySlots,
      proxyImplementationCodeHashes,
      versions: {
        // Resolved from the loaded config, not restated. The hardcoded values drifted: the record claimed
        // optimizer runs 1 for every contract regardless of what was actually compiled.
        solidity: config.solidity.compilers.map((c) => ({
          version: c.version,
          settings: c.settings,
        })),
        solidityOverrides: Object.fromEntries(
          Object.entries(config.solidity.overrides ?? {}).map(([k, v]) => [
            k,
            { version: v.version, settings: v.settings },
          ]),
        ),
        // eslint-disable-next-line @typescript-eslint/no-require-imports
        hardhat: require("hardhat/package.json").version,
        noir: "1.0.0-beta.22",
        bbjs: "5.0.0",
      },
      circuitHashes,
      vkHashes,
      openzeppelinManifest,
      feeAssets,
    };
  }

  async function writeRecord(latest: boolean): Promise<string> {
    const record = buildRecord(await ethers.provider.getBlockNumber());
    fs.writeFileSync(deployFile, JSON.stringify(record, null, 2));
    if (latest) fs.writeFileSync(latestFile, JSON.stringify(record, null, 2));
    return deployFile;
  }

  await writeRecord(true);
  console.log(`Deployment record: ${deployFile}`);
  console.log(`Latest pointer:    ${latestFile}`);
  console.log();

  console.log("DEPLOYMENT COMPLETE");
  console.log(`  Timelock:      ${timelockAddr}`);
  console.log(`  DarkPool:      ${darkPoolAddr}`);
  console.log(`  NoxRegistry:   ${noxRegistryAddr}`);
  console.log(`  NoxRewardPool: ${rewardPoolAddr}`);
  console.log(`  NoxEntryPoint: ${noxEntryPointAddr}`);
  console.log(`  Howl Adapter:  ${howlPaymentAdapterAddr}`);
  console.log(`  BundleExecutor:${bundleExecutorAddr}`);
  console.log(`  Staking Token: ${stakingTokenAddr}`);
  if (adaptorAddr) console.log(`  UniswapAdaptor:${adaptorAddr}`);
  console.log();

  if (isLocal) {
    console.log("Local ephemeral deployment; no private backup is required.");
  } else {
    console.log("REQUIRED BACKUP - push these to the private backup repo now:");
    console.log(
      `  - ${deployFile} (addresses, proxy slots, circuit hashes, VK hashes, storage manifest)`,
    );
    if (suppliedSk === undefined) {
      console.log(
        `  - ${secretsFile} (COMPLIANCE SECRET KEY, written before any transaction, mode 0600)`,
      );
      console.log(
        "    Move it into the secrets vault and remove the local copy. Losing it makes every note",
      );
      console.log(
        "    encrypted to the compliance key permanently undecryptable.",
      );
    } else {
      console.log(
        "  - COMPLIANCE_SECRET_KEY was supplied via env; ensure it is already backed up.",
      );
    }
    console.log();
    console.log("The deployment is not done until the backup is pushed.");
  }

  return {
    deployment: buildRecord(await ethers.provider.getBlockNumber()),
    deployFile,
    secretsFile: suppliedSk === undefined ? secretsFile : null,
  };
}

if (require.main === module) {
  deploy()
    .then(() => process.exit(0))
    .catch((error) => {
      console.error(error);
      process.exit(1);
    });
}
