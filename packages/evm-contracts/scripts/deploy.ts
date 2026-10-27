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
 *                  admin + distributor. Explicitly NOT a Timelock canceller. Off test chains no owner of
 *                  one Safe may own the other, and each Safe needs a threshold of at least 2, no enabled
 *                  module and no guard (warnings on test chains), and must be a proxy whose singleton is
 *                  an official Safe v1.3.0 or v1.4.1 singleton (SAFE_SINGLETONS).
 *   STAKING_TOKEN  ERC20 staking token. Required off local; a dev MockERC20 is deployed only on
 *                  hardhat/localhost, because it has an unpermissioned mint and NoxRegistry writes the
 *                  token once with no update path. Off test chains it must be the chain's WETH or USDC.
 * Required off the test chains (SHORT_DELAY_CHAIN_IDS), optional on them:
 *   COMPLIANCE_PUBLIC_KEY_X, COMPLIANCE_PUBLIC_KEY_Y  the compliance public key (the committee key); no
 *                          secret touches this machine. Off test chains this is the only accepted source.
 *   MIN_STAKE, MIN_STAKE_FLOOR  Nox stake and its permanent floor, in whole staking tokens (decimals read
 *                          from the token), e.g. 1000 or 0.5. Default 1 each on test chains.
 * Optional env:
 *   COMPLIANCE_SECRET_KEY  test chains only: reuse an existing compliance BJJ secret (else one is generated
 *                          and written to the sibling .secrets.json before any deploy transaction)
 *   LOCAL_TEST_COMPLIANCE_SECRET_KEY  deterministic fixture accepted only by hardhat/localhost
 *   SWAP_ROUTER            deploy UniswapAdaptor against this router
 *   FEE_ASSETS             comma-separated ERC20 addresses accepted for Nox execution fees; required off local,
 *                          and off test chains exactly the chain's USDC
 *   MULTISIG_VERIFIERS     "stub" or "real": what the four multisig circuit slots hold. Off test chains only
 *                          "stub" (a RevertingVerifier until the Timelock installs the real ones); default
 *                          "real" on test chains. While the stub holds them, every multisig action reverts,
 *                          including multisig Nox fee payments through the multisig payment adapter.
 *   KAGE_MODULE            "on" deploys the Kage settlement module (KageRegistry proxy + KageSettlement) and
 *                          writes the Timelock call that registers it; default "off", and refused off test chains
 *                          while the Kage launch is parked. With it on:
 *     KAGE_STAKING_TOKEN   solver stake token; required off local (local default: the Nox staking token)
 *     KAGE_MIN_STAKE, KAGE_MIN_STAKE_FLOOR  in whole tokens, scaled by its decimals (default 1 each on test chains)
 *     KAGE_EXIT_DELAY_SECS solver exit delay, at least 86400 (default 604800 = 7 days)
 *   TIMELOCK_MIN_DELAY_SECS    Timelock minimum delay in seconds (default 172800 = 48h)
 *   ADMIN_TRANSFER_DELAY_SECS  AccessControlDefaultAdminRules DEFAULT_ADMIN transfer delay in seconds on
 *                              DarkPool, NoxRegistry and NoxRewardPool (default 172800 = 48h)
 *                          Either may be 0, but a value below 48h is refused outside SHORT_DELAY_CHAIN_IDS.
 *   SKIP_EXPLORER_VERIFY   "true" skips block-explorer verification (forks and rehearsals)
 *   FORCE_LAUNCH_RULES     "1" makes chain 31337 (a hardhat fork rehearsal) enforce every launch-chain refusal,
 *                          evaluated for the forked chain when Hardhat reports a fork of a non-test chain, else
 *                          for 31337 itself, which has no token row and so refuses any staking or fee token
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
import {
  Base8,
  inCurve,
  mulPointEscalar,
  Point,
  r as BN254_FR,
} from "@zk-kit/baby-jubjub";
import { Manifest } from "@openzeppelin/upgrades-core";
import type { BaseContract } from "ethers";

const BJJ_SUBGROUP_ORDER =
  2736030358979909402780800718157159386076813972158567259200215660948447373041n;

// Production default: a 48h timelock, and a 2-step DEFAULT_ADMIN transfer delay (AccessControlDefaultAdminRules)
// that matches it.
const DEFAULT_GOVERNANCE_DELAY = 48n * 60n * 60n;
const UINT48_MAX = 2n ** 48n - 1n;
// The test chains: the in-process chain, Arbitrum Sepolia and Sepolia. A delay below the production default is a
// testnet affordance; anywhere else it would hand governance an instant path around the review window. Every other
// launch-chain rule below (fee asset, staking token, stake amounts, compliance key source, Safe owners and controls,
// multisig verifier stub) is likewise relaxed only here.
const IN_PROCESS_CHAIN_ID = 31337n;
const SHORT_DELAY_CHAIN_IDS: ReadonlySet<bigint> = new Set([
  IN_PROCESS_CHAIN_ID,
  421614n,
  11155111n,
]);

const UNSTAKE_DELAY = 86400n; // contract minimum (1 day)
const TEST_CHAIN_STAKE = "1";

/**
 * FORCE_LAUNCH_RULES=1 makes the in-process chain enforce every launch-chain refusal, so a fork rehearsal under
 * chain id 31337 rehearses the launch rules rather than the relaxed test-chain ones. Any other non-empty value is
 * refused, so a typo cannot silently fall back to the relaxed rules.
 */
export function launchRulesForced(): boolean {
  const raw = (process.env.FORCE_LAUNCH_RULES ?? "").trim();
  if (raw !== "" && raw !== "1") {
    throw new Error(`FORCE_LAUNCH_RULES=${raw} must be "1" or unset.`);
  }
  return raw === "1";
}

export function isTestChain(chainId: bigint): boolean {
  if (chainId === IN_PROCESS_CHAIN_ID && launchRulesForced()) return false;
  return SHORT_DELAY_CHAIN_IDS.has(chainId);
}

/**
 * The chain id the launch rules are evaluated against. A forced rehearsal on a fork of a launch chain takes the
 * forked chain's token row; a forced run with no fork, or on a fork of a test chain, keeps 31337, which has no
 * token row and so refuses every staking and fee token.
 */
export function launchRulesChainId(
  chainId: bigint,
  forkedChainId: bigint | null,
): bigint {
  if (chainId !== IN_PROCESS_CHAIN_ID || !launchRulesForced()) return chainId;
  if (forkedChainId === null || SHORT_DELAY_CHAIN_IDS.has(forkedChainId)) {
    return chainId;
  }
  return forkedChainId;
}

// Hardhat's own metadata call names the forked chain; any other node (anvil, a live RPC) does not answer it, and a
// fork there is rehearsed under the forked chain's own id instead.
async function forkedChainId(): Promise<bigint | null> {
  let metadata: { forkedNetwork?: { chainId: number } };
  try {
    metadata = await ethers.provider.send("hardhat_metadata", []);
  } catch {
    return null;
  }
  return metadata.forkedNetwork === undefined
    ? null
    : BigInt(metadata.forkedNetwork.chainId);
}

export interface LaunchTokens {
  readonly usdc: string;
  readonly weth: string;
}

// Native Circle USDC (developers.circle.com/stablecoins/usdc-contract-addresses) and the chain's canonical WETH.
// A launch chain missing here is refused until its row is added and reviewed.
const USDC_DECIMALS = 6n;
const WETH_DECIMALS = 18n;
export const LAUNCH_TOKENS: ReadonlyMap<bigint, LaunchTokens> = new Map([
  [
    1n,
    {
      usdc: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
      weth: "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
    },
  ],
  [
    10n,
    {
      usdc: "0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85",
      weth: "0x4200000000000000000000000000000000000006",
    },
  ],
  [
    8453n,
    {
      usdc: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
      weth: "0x4200000000000000000000000000000000000006",
    },
  ],
  [
    42161n,
    {
      usdc: "0xaf88d065e77c8cC2239327C5EDb3A432268e5831",
      weth: "0x82aF49447D8a07e3bd95BD0d56f35241523fBab1",
    },
  ],
]);

function launchTokens(chainId: bigint): LaunchTokens {
  const tokens = LAUNCH_TOKENS.get(chainId);
  if (tokens === undefined) {
    throw new Error(
      `chain id ${chainId} has no USDC/WETH row in LAUNCH_TOKENS; add the chain's native USDC and canonical WETH ` +
        "addresses (reviewed) before deploying there.",
    );
  }
  return tokens;
}

/** Off the test chains, refuses any fee asset that is not the chain's USDC; the staking token is never the default. */
export function assertFeeAssets(
  chainId: bigint,
  feeAssets: readonly string[],
  stakingToken: string,
): void {
  if (isTestChain(chainId)) return;
  const { usdc } = launchTokens(chainId);
  if (feeAssets.length === 0) {
    throw new Error(
      `FEE_ASSETS is empty; on chain id ${chainId} it must be USDC ${usdc}.`,
    );
  }
  for (const asset of feeAssets) {
    if (ethers.getAddress(asset) === usdc) continue;
    if (ethers.getAddress(asset) === ethers.getAddress(stakingToken)) {
      throw new Error(
        `FEE_ASSETS entry ${asset} is the staking token; on chain id ${chainId} the Nox fee asset is USDC ${usdc} only.`,
      );
    }
    throw new Error(
      `FEE_ASSETS entry ${asset} is not USDC; on chain id ${chainId} the Nox fee asset is USDC ${usdc} only.`,
    );
  }
}

/** Off the test chains, the staking token is the chain's WETH or USDC, with the decimals that token is known to have. */
export function assertStakingToken(
  chainId: bigint,
  stakingToken: string,
  decimals: bigint,
): void {
  if (isTestChain(chainId)) return;
  const { usdc, weth } = launchTokens(chainId);
  const token = ethers.getAddress(stakingToken);
  const expected =
    token === weth ? WETH_DECIMALS : token === usdc ? USDC_DECIMALS : null;
  if (expected === null) {
    throw new Error(
      `STAKING_TOKEN ${token} is neither WETH ${weth} nor USDC ${usdc} on chain id ${chainId}.`,
    );
  }
  if (decimals !== expected) {
    throw new Error(
      `STAKING_TOKEN ${token} reports ${decimals} decimals, expected ${expected}.`,
    );
  }
}

const TOKEN_AMOUNT_RE = /^[0-9]+(\.[0-9]+)?$/;

function tokenAmount(name: string, raw: string, decimals: bigint): bigint {
  const trimmed = raw.trim();
  if (!TOKEN_AMOUNT_RE.test(trimmed)) {
    throw new Error(
      `${name}=${raw} must be a decimal amount of whole staking tokens, e.g. 1000 or 0.5.`,
    );
  }
  const fraction = trimmed.split(".")[1] ?? "";
  if (BigInt(fraction.length) > decimals) {
    throw new Error(
      `${name}=${raw} has more fractional digits than the staking token's ${decimals} decimals.`,
    );
  }
  const amount = ethers.parseUnits(trimmed, Number(decimals));
  if (amount <= 0n) throw new Error(`${name}=${raw} must be positive.`);
  if (amount > ethers.MaxUint256) throw new Error(`${name} exceeds uint256.`);
  return amount;
}

/**
 * MIN_STAKE and MIN_STAKE_FLOOR in the staking token's base units. NoxRegistry writes the floor once and refuses a
 * stake below it forever, so a unit error (18-decimal literals against a 6-decimal token) cannot be repaired
 * without an upgrade. Required off the test chains; 1 token each by default on them.
 */
export function stakeAmounts(
  chainId: bigint,
  decimals: bigint,
  prefix: "" | "KAGE_" = "",
): { minStake: bigint; minStakeFloor: bigint } {
  const minStakeName = `${prefix}MIN_STAKE`;
  const floorName = `${prefix}MIN_STAKE_FLOOR`;
  const read = (name: string): bigint => {
    const raw = process.env[name];
    if (raw === undefined || raw.trim() === "") {
      if (!isTestChain(chainId)) {
        throw new Error(
          `${name} is required on chain id ${chainId}; give it in whole staking tokens.`,
        );
      }
      return tokenAmount(name, TEST_CHAIN_STAKE, decimals);
    }
    return tokenAmount(name, raw, decimals);
  };
  const minStake = read(minStakeName);
  const minStakeFloor = read(floorName);
  if (minStake < minStakeFloor) {
    throw new Error(
      `${minStakeName} (${minStake} base units) is below ${floorName} (${minStakeFloor}); the registry refuses it.`,
    );
  }
  return { minStake, minStakeFloor };
}

export interface SafeOwnership {
  readonly label: string;
  readonly address: string;
  readonly owners: readonly string[];
  readonly threshold: bigint;
}

/**
 * Owners that sit on both Safes. One shared owner already lets the guardian side contribute to a governance
 * signature, and enough of them let the guardian alone meet the Gov threshold, so any overlap is refused off the
 * test chains. Returns the shared owners.
 */
export function assertSafeOwnersDisjoint(
  chainId: bigint,
  gov: SafeOwnership,
  guardian: SafeOwnership,
): string[] {
  const govOwners = new Set(gov.owners.map((o) => ethers.getAddress(o)));
  const shared = guardian.owners
    .map((o) => ethers.getAddress(o))
    .filter((o) => govOwners.has(o));
  if (shared.length > 0 && !isTestChain(chainId)) {
    throw new Error(
      `${guardian.label} ${guardian.address} (${guardian.threshold}-of-${guardian.owners.length}) shares owner(s) ` +
        `${shared.join(", ")} with ${gov.label} ${gov.address} (${gov.threshold}-of-${gov.owners.length}); the two ` +
        "Safes must have disjoint owners.",
    );
  }
  return shared;
}

// Safe v1.x storage: the guard sits at keccak256("guard_manager.guard.address"); modules are a linked list read from
// the sentinel. One page is enough, since any enabled module is refused.
const SAFE_ABI = [
  "function getOwners() view returns (address[])",
  "function getThreshold() view returns (uint256)",
  "function getModulesPaginated(address start, uint256 pageSize) view returns (address[] array, address next)",
];
const SAFE_GUARD_SLOT = ethers.id("guard_manager.guard.address");
const SAFE_MODULES_SENTINEL = "0x0000000000000000000000000000000000000001";
const SAFE_MODULES_PAGE = 10;
const MIN_SAFE_THRESHOLD = 2n;

export interface SafeControls extends SafeOwnership {
  readonly modules: readonly string[];
  /** The raw guard storage word; any non-zero word counts as a guard. */
  readonly guardWord: string;
  /** The raw storage word at slot 0, where a Safe proxy keeps its singleton. */
  readonly singletonWord: string;
}

// Official Safe singletons, from safe-global/safe-deployments at commit b45417dd009957effb3575928941e736f8fd37d1:
// src/assets/v1.3.0/gnosis_safe.json and gnosis_safe_l2.json (canonical and eip155 deployments), and
// src/assets/v1.4.1/safe.json and safe_l2.json (canonical). Each address is listed there for chains 1, 10, 8453
// and 42161. They are CREATE2 deployments, so an address carries the same reviewed code on every chain that has
// it. Both versions keep the guard at the slot SAFE_GUARD_SLOT reads and the modules in the list
// getModulesPaginated walks, which is what assertSafeControls checks. v1.5.0 adds a module guard at another slot
// and is left out until those checks cover it.
export const SAFE_SINGLETONS: ReadonlyMap<string, string> = new Map([
  [
    "0xd9Db270c1B5E3Bd161E8c8503c55cEABeE709552",
    "v1.3.0 GnosisSafe (canonical)",
  ],
  ["0x69f4D1788e39c87893C980c06EdF4b7f686e2938", "v1.3.0 GnosisSafe (eip155)"],
  [
    "0x3E5c63644E683549055b9Be8653de26E0B4CD36E",
    "v1.3.0 GnosisSafeL2 (canonical)",
  ],
  [
    "0xfb1bffC9d739B8D520DaF37dF666da4C687191EA",
    "v1.3.0 GnosisSafeL2 (eip155)",
  ],
  ["0x41675C099F32341bf84BFc5382aF534df5C7461a", "v1.4.1 Safe (canonical)"],
  ["0x29fcB43b46531BcA003ddC8FCB67FFE91900C762", "v1.4.1 SafeL2 (canonical)"],
]);
const SAFE_SINGLETON_SLOT = 0n;

/**
 * Off the test chains, refuses a Safe whose proxy does not point at an official Safe singleton: a contract that
 * merely answers the Safe getters can report any owners, threshold, modules and guard. Returns the singleton's
 * description, or null on a test chain where it is not one.
 */
export function assertSafeSingleton(
  chainId: bigint,
  safe: SafeControls,
): string | null {
  const word = safe.singletonWord.toLowerCase();
  const highBytesClear = /^0x0{24}[0-9a-f]{40}$/.test(word);
  const singleton = highBytesClear
    ? ethers.getAddress(ethers.dataSlice(word, 12))
    : null;
  const known = singleton === null ? undefined : SAFE_SINGLETONS.get(singleton);
  if (known !== undefined) return known;
  if (isTestChain(chainId)) return null;
  throw new Error(
    `${safe.label} ${safe.address} has storage slot 0 ${safe.singletonWord}, which is not an official Safe ` +
      "v1.3.0 or v1.4.1 singleton (SAFE_SINGLETONS); a launch Safe must be a Safe proxy deployed from the " +
      "official contracts.",
  );
}

/**
 * What lets a Safe act around a quorum of its owners: a threshold below 2 makes one key the whole Safe, an enabled
 * module executes without owner signatures, and a guard can veto or rewrite every Safe transaction. Off the test
 * chains each is refused; on them the problems are returned for a warning.
 */
export function assertSafeControls(
  chainId: bigint,
  safe: SafeControls,
): string[] {
  const problems: string[] = [];
  if (safe.threshold < MIN_SAFE_THRESHOLD) {
    problems.push(
      `threshold ${safe.threshold}-of-${safe.owners.length} is below ${MIN_SAFE_THRESHOLD}`,
    );
  }
  if (safe.modules.length > 0) {
    problems.push(`module(s) enabled: ${safe.modules.join(", ")}`);
  }
  if (safe.guardWord !== ethers.ZeroHash) {
    problems.push(`guard ${ethers.dataSlice(safe.guardWord, 12)} is set`);
  }
  if (problems.length > 0 && !isTestChain(chainId)) {
    throw new Error(
      `${safe.label} ${safe.address} ${problems.join("; ")}; a launch Safe needs a threshold of at least ` +
        `${MIN_SAFE_THRESHOLD}, no module and no guard.`,
    );
  }
  return problems;
}

async function readSafe(label: string, address: string): Promise<SafeControls> {
  const safe = new ethers.Contract(address, SAFE_ABI, ethers.provider);
  try {
    const owners = ((await safe.getOwners()) as string[]).map((o) =>
      ethers.getAddress(o),
    );
    const threshold = BigInt(await safe.getThreshold());
    if (owners.length === 0 || threshold === 0n) {
      throw new Error(`owners ${owners.length}, threshold ${threshold}`);
    }
    const [modules] = (await safe.getModulesPaginated(
      SAFE_MODULES_SENTINEL,
      SAFE_MODULES_PAGE,
    )) as [string[], string];
    return {
      label,
      address,
      owners,
      threshold,
      modules: modules.map((m) => ethers.getAddress(m)),
      guardWord: await ethers.provider.getStorage(address, SAFE_GUARD_SLOT),
      singletonWord: await ethers.provider.getStorage(
        address,
        SAFE_SINGLETON_SLOT,
      ),
    };
  } catch (e) {
    const detail = e instanceof Error ? e.message : String(e);
    throw new Error(
      `${label} ${address} does not answer as a Safe (getOwners/getThreshold/getModulesPaginated): ${detail}`,
    );
  }
}

export type MultisigVerifierMode = "stub" | "real";

/**
 * What the four multisig circuit slots hold. Off the test chains they hold a RevertingVerifier until production
 * DKG, after which the Timelock installs the real verifiers with setVerifier.
 */
export function multisigVerifierMode(chainId: bigint): MultisigVerifierMode {
  const raw = (process.env.MULTISIG_VERIFIERS ?? "").trim();
  if (raw !== "" && raw !== "stub" && raw !== "real") {
    throw new Error(`MULTISIG_VERIFIERS=${raw} must be "stub" or "real".`);
  }
  if (isTestChain(chainId)) return raw === "stub" ? "stub" : "real";
  if (raw === "real") {
    throw new Error(
      `MULTISIG_VERIFIERS=real is refused on chain id ${chainId}; the multisig slots ship the RevertingVerifier ` +
        "and the Timelock installs the real verifiers after production DKG.",
    );
  }
  return "stub";
}

function bjjCoordinate(name: string, raw: string): bigint {
  let value: bigint;
  try {
    value = BigInt(raw.trim());
  } catch {
    throw new Error(`${name} must be an unsigned decimal or 0x-hex integer.`);
  }
  if (value < 0n || value >= BN254_FR) {
    throw new Error(`${name} is outside the BN254 scalar field.`);
  }
  return value;
}

// Kage's registration tuple: two spent notes (taker, maker), four minted self-notes, no module words, and a proof
// timestamp that may not lie in the past, so a swap settles before its intent expires or not at all.
export const KAGE_MODULE_LAYOUT = {
  nullifierCount: 2n,
  outputCount: 4n,
  extraCount: 0n,
  maxPast: 0n,
  maxFuture: 2n ** 32n - 1n,
} as const;
const KAGE_MIN_EXIT_DELAY = 86400n;
const KAGE_DEFAULT_EXIT_DELAY = 7n * 86400n;

/** "on" deploys the Kage module; refused off the test chains while the Kage launch is parked. */
export function kageModuleEnabled(chainId: bigint): boolean {
  const raw = (process.env.KAGE_MODULE ?? "").trim();
  if (raw !== "" && raw !== "on" && raw !== "off") {
    throw new Error(`KAGE_MODULE=${raw} must be "on" or "off".`);
  }
  if (raw !== "on") return false;
  if (!isTestChain(chainId)) {
    throw new Error(
      `KAGE_MODULE=on is refused on chain id ${chainId}: the Kage launch is parked, so its registry and module ` +
        "are deployed on test chains only.",
    );
  }
  return true;
}

export function kageExitDelay(): bigint {
  const raw = process.env.KAGE_EXIT_DELAY_SECS;
  if (raw === undefined || raw.trim() === "") return KAGE_DEFAULT_EXIT_DELAY;
  if (!/^[0-9]+$/.test(raw.trim())) {
    throw new Error(
      `KAGE_EXIT_DELAY_SECS=${raw} must be an unsigned decimal number of seconds.`,
    );
  }
  const value = BigInt(raw.trim());
  if (value < KAGE_MIN_EXIT_DELAY) {
    throw new Error(
      `KAGE_EXIT_DELAY_SECS=${raw} is below the registry minimum of ${KAGE_MIN_EXIT_DELAY}s.`,
    );
  }
  return value;
}

/** The Timelock call that registers `settlement` as the Kage module on `darkPool`. */
export function kageModuleRegistration(
  darkPool: string,
  settlement: string,
  kageVerifier: string,
): { target: string; value: string; data: string } {
  const iface = new ethers.Interface([
    "function registerSettlementModule(address controller, address moduleVerifier, uint8 nullifierCount, uint8 outputCount, uint8 extraCount, uint32 maxPast, uint32 maxFuture)",
  ]);
  const l = KAGE_MODULE_LAYOUT;
  return {
    target: darkPool,
    value: "0",
    data: iface.encodeFunctionData("registerSettlementModule", [
      settlement,
      kageVerifier,
      l.nullifierCount,
      l.outputCount,
      l.extraCount,
      l.maxPast,
      l.maxFuture,
    ]),
  };
}

/**
 * Compares the module DarkPool holds for `settlement` with the Kage layout. Run once the Timelock has executed the
 * registration: settle-before-expiry depends on `maxPast == 0`, and a controller can never re-register.
 */
export async function kageModuleProblems(
  darkPool: BaseContract,
  settlement: string,
  kageVerifier: string,
): Promise<string[]> {
  const m = (await darkPool.getFunction("settlementModule")(settlement)) as {
    verifier: string;
    nullifierCount: bigint;
    outputCount: bigint;
    extraCount: bigint;
    maxPast: bigint;
    maxFuture: bigint;
    active: boolean;
  };
  const problems: string[] = [];
  if (m.verifier === ethers.ZeroAddress) {
    return [`no settlement module is registered for ${settlement}`];
  }
  if (m.verifier !== kageVerifier) {
    problems.push(`module verifier is ${m.verifier}, expected ${kageVerifier}`);
  }
  for (const field of Object.keys(
    KAGE_MODULE_LAYOUT,
  ) as (keyof typeof KAGE_MODULE_LAYOUT)[]) {
    if (BigInt(m[field]) !== KAGE_MODULE_LAYOUT[field]) {
      problems.push(
        `${field} is ${m[field]}, expected ${KAGE_MODULE_LAYOUT[field]}`,
      );
    }
  }
  if (!m.active) problems.push("module is not active");
  return problems;
}

/** On-curve, not the identity, and in the prime-order subgroup: the checks the circuits apply to the key. */
export function assertCompliancePublicKey(pk: Point<bigint>): void {
  if (!inCurve(pk)) {
    throw new Error("compliance public key is not on the BabyJubJub curve.");
  }
  if (pk[0] === 0n && pk[1] === 1n) {
    throw new Error("compliance public key is the identity point.");
  }
  const cofactorCleared = mulPointEscalar(pk, BJJ_SUBGROUP_ORDER);
  if (cofactorCleared[0] !== 0n || cofactorCleared[1] !== 1n) {
    throw new Error(
      "compliance public key is not in the BabyJubJub prime-order subgroup.",
    );
  }
}

export type ComplianceKeySource =
  | "public-key"
  | "supplied-secret"
  | "local-fixture"
  | "generated";

export interface ComplianceKey {
  readonly source: ComplianceKeySource;
  readonly pk: Point<bigint>;
  /** Present only when this run knows the secret: generated, supplied or the local fixture. */
  readonly sk: bigint | null;
}

/**
 * Resolves the compliance key from exactly one source. Off the test chains only a public key is accepted: the
 * launch key is the committee's, which has no single secret, and a secret generated or pasted here would leave one
 * machine able to decrypt every note forever.
 */
export function resolveComplianceKey(
  chainId: bigint,
  isLocal: boolean,
): ComplianceKey {
  const env = (name: string): string | undefined => {
    const raw = process.env[name];
    return raw === undefined || raw.trim() === "" ? undefined : raw;
  };
  const configuredSk = env("COMPLIANCE_SECRET_KEY");
  const localFixtureSk = env("LOCAL_TEST_COMPLIANCE_SECRET_KEY");
  const pkX = env("COMPLIANCE_PUBLIC_KEY_X");
  const pkY = env("COMPLIANCE_PUBLIC_KEY_Y");
  if (configuredSk !== undefined && localFixtureSk !== undefined) {
    throw new Error(
      "Set only one of COMPLIANCE_SECRET_KEY or LOCAL_TEST_COMPLIANCE_SECRET_KEY.",
    );
  }
  if ((pkX === undefined) !== (pkY === undefined)) {
    throw new Error(
      "Set both COMPLIANCE_PUBLIC_KEY_X and COMPLIANCE_PUBLIC_KEY_Y, or neither.",
    );
  }
  if (
    pkX !== undefined &&
    (configuredSk !== undefined || localFixtureSk !== undefined)
  ) {
    throw new Error(
      "Set either COMPLIANCE_PUBLIC_KEY_X/Y or a compliance secret, not both.",
    );
  }
  if (localFixtureSk !== undefined && !isLocal) {
    throw new Error(
      "LOCAL_TEST_COMPLIANCE_SECRET_KEY is accepted only on hardhat or localhost, and not under FORCE_LAUNCH_RULES=1.",
    );
  }
  if (pkX !== undefined && pkY !== undefined) {
    const pk: Point<bigint> = [
      bjjCoordinate("COMPLIANCE_PUBLIC_KEY_X", pkX),
      bjjCoordinate("COMPLIANCE_PUBLIC_KEY_Y", pkY),
    ];
    assertCompliancePublicKey(pk);
    return { source: "public-key", pk, sk: null };
  }
  if (!isTestChain(chainId)) {
    throw new Error(
      `chain id ${chainId} takes the compliance key as COMPLIANCE_PUBLIC_KEY_X/Y only (the committee key); a ` +
        "generated or supplied secret is accepted only on test chains.",
    );
  }
  const suppliedSk = configuredSk ?? localFixtureSk;
  if (suppliedSk === undefined) {
    const generated = generateComplianceKeypair();
    return { source: "generated", ...generated };
  }
  const suppliedSkName =
    configuredSk === undefined
      ? "LOCAL_TEST_COMPLIANCE_SECRET_KEY"
      : "COMPLIANCE_SECRET_KEY";
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
  return {
    source: configuredSk === undefined ? "local-fixture" : "supplied-secret",
    pk: mulPointEscalar(Base8, sk),
    sk,
  };
}

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
    if (value < DEFAULT_GOVERNANCE_DELAY && !isTestChain(chainId)) {
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

export interface VerifierSpec {
  /** Key in the deployment record's `contracts`. */
  readonly key: string;
  readonly source: string;
  readonly contract: string;
}

const honk = (key: string, file: string): VerifierSpec => ({
  key,
  source: `contracts/verifiers/${file}.sol`,
  contract: "HonkVerifier",
});

// Index = circuit id; the order MUST match the circuit-id constants in DarkPool.sol (deposit=0 .. join_multisig=9).
// There is no deposit_multisig verifier: deposit is unified and mints a MULTISIG note from a private witness.
export const CIRCUIT_VERIFIERS: readonly VerifierSpec[] = [
  honk("depositVerifier", "DepositVerifier"),
  honk("withdrawVerifier", "WithdrawVerifier"),
  honk("transferVerifier", "TransferVerifier"),
  honk("joinVerifier", "JoinVerifier"),
  honk("splitVerifier", "SplitVerifier"),
  honk("publicClaimVerifier", "PublicClaimVerifier"),
  honk("withdrawMultisigVerifier", "WithdrawMultisigVerifier"),
  honk("transferMultisigVerifier", "TransferMultisigVerifier"),
  honk("splitMultisigVerifier", "SplitMultisigVerifier"),
  honk("joinMultisigVerifier", "JoinMultisigVerifier"),
];
export const MULTISIG_CIRCUIT_IDS: ReadonlySet<number> = new Set([6, 7, 8, 9]);
export const KAGE_VERIFIER: VerifierSpec = honk("kageVerifier", "KageVerifier");
export const REVERTING_VERIFIER: VerifierSpec = {
  key: "revertingVerifier",
  source: "contracts/verifiers-stub/RevertingVerifier.sol",
  contract: "RevertingVerifier",
};

function verifierName(spec: VerifierSpec): string {
  return path.basename(spec.source, ".sol");
}

function requireDeployed(
  deployed: ReadonlyMap<VerifierSpec, string>,
  spec: VerifierSpec,
): string {
  const address = deployed.get(spec);
  if (address === undefined) {
    throw new Error(`${verifierName(spec)} was not deployed in this run.`);
  }
  return address;
}

async function deployVerifier(spec: VerifierSpec): Promise<string> {
  const factory = await ethers.getContractFactory(
    `${spec.source}:${spec.contract}`,
  );
  const verifier = await factory.deploy();
  await verifier.waitForDeployment();
  const addr = await verifier.getAddress();
  console.log(`    ${verifierName(spec)}: ${addr}`);
  return addr;
}

const DEV_STAKING_TOKEN_DECIMALS = 18n;

async function tokenDecimals(label: string, token: string): Promise<bigint> {
  const erc20 = new ethers.Contract(
    token,
    ["function decimals() view returns (uint8)"],
    ethers.provider,
  );
  try {
    return BigInt(await erc20.decimals());
  } catch (e) {
    const detail = e instanceof Error ? e.message : String(e);
    throw new Error(`${label} ${token} does not answer decimals(): ${detail}`);
  }
}

const COMPLIANCE_SOURCE_LABELS: Readonly<Record<ComplianceKeySource, string>> =
  {
    "public-key":
      "Using the supplied compliance public key; no compliance secret exists on this machine",
    "supplied-secret": "Reusing supplied compliance keypair",
    "local-fixture": "Using deterministic local test compliance keypair",
    generated: "Generated a fresh compliance keypair",
  };

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

// Backend metadata read from the verifier source compiled and deployed in this run: a Honk verifier carries a
// VK_HASH binding it to a circuit build, another proving system or the stub may carry none. The verifier's identity
// in the record is its extcodehash, which every backend has.
function verifierVkHash(contractPath: string): string | null {
  const src = fs.readFileSync(path.join(__dirname, "..", contractPath), "utf8");
  return src.match(VK_HASH_RE)?.[1] ?? null;
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

/**
 * The record and secrets base name for one run: the network, the UTC time to the millisecond and a random suffix,
 * so two runs never share a name, even in the same millisecond or across machines writing to one directory.
 */
export function deploymentBaseName(
  networkName: string,
  now: Date = new Date(),
  suffix: string = crypto.randomBytes(4).toString("hex"),
): string {
  const stamp = now.toISOString().replace(/[:.]/g, "-").slice(0, 23);
  return `${networkName}-${stamp}-${suffix}`;
}

/**
 * Creates `file` and refuses if it already exists: a record or a compliance secret from another run is never
 * overwritten, since a lost secret leaves every note encrypted to its key undecryptable.
 */
export function writeNewFile(
  file: string,
  content: string,
  mode: number = 0o666,
): void {
  try {
    fs.writeFileSync(file, content, { flag: "wx", mode });
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "EEXIST") {
      throw new Error(
        `${file} already exists; refusing to overwrite another deployment's file. Re-run to get a fresh name.`,
      );
    }
    throw e;
  }
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
  const forced = launchRulesForced();
  // The launch refusals keyed on the network name (an EOA Safe, a missing staking token or fee asset, the local
  // compliance fixture, a missing circuit artifact or storage manifest) are lifted only on an unforced local run.
  // The redeploy guard, explorer verification and backup notice concern a persistent chain and stay on isLocal.
  const relaxLocalRules = isLocal && !forced;
  const rulesChainId = launchRulesChainId(chainId, await forkedChainId());

  const { timelockMinDelay, adminTransferDelay } =
    governanceDelays(rulesChainId);

  const govSafe = requireSafeAddress("GOV_SAFE");
  const guardianSafe = requireSafeAddress("GUARDIAN_SAFE");
  const stakingToken = optionalAddress("STAKING_TOKEN");
  const swapRouter = optionalAddress("SWAP_ROUTER");
  const explicitFeeAssets = configuredFeeAssets(relaxLocalRules);
  const committeeThreshold = positiveUint256("COMPLIANCE_THRESHOLD", "3");
  const committeeSize = positiveUint256("COMPLIANCE_COMMITTEE_SIZE", "5");
  if (committeeThreshold > committeeSize) {
    throw new Error(
      "COMPLIANCE_THRESHOLD must not exceed COMPLIANCE_COMMITTEE_SIZE.",
    );
  }
  const compliance = resolveComplianceKey(rulesChainId, relaxLocalRules);
  const multisigVerifiers = multisigVerifierMode(rulesChainId);
  const kageEnabled = kageModuleEnabled(rulesChainId);
  // One address holding both roles collapses the separation the wiring assertions exist to enforce, and
  // every one of them would still pass.
  if (govSafe === guardianSafe) {
    throw new Error(
      `GOV_SAFE and GUARDIAN_SAFE are the same address (${govSafe}); the pauser must not also hold the veto.`,
    );
  }

  console.log("DarkPool + NOX governed deployment");
  console.log(`  Network:       ${network.name} (chainId: ${chainId})`);
  if (forced) {
    console.log(
      `  FORCE_LAUNCH_RULES=1: launch-chain rules enforced, evaluated for chain id ${rulesChainId}`,
    );
  }
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
  const safeOwnerships: SafeControls[] = [];
  for (const [label, addr] of [
    ["GOV_SAFE", govSafe],
    ["GUARDIAN_SAFE", guardianSafe],
  ] as const) {
    if ((await ethers.provider.getCode(addr)) !== "0x") {
      const safe = await readSafe(label, addr);
      const singleton = assertSafeSingleton(rulesChainId, safe);
      if (singleton !== null) {
        console.log(`  ${label} singleton: ${singleton}`);
      }
      const problems = assertSafeControls(rulesChainId, safe);
      if (problems.length > 0) {
        console.log(
          `  WARNING: ${label} ${addr} ${problems.join("; ")}; accepted only on test chain ${chainId}.`,
        );
      }
      safeOwnerships.push(safe);
    } else {
      // An EOA here is not a weaker multisig, it is no multisig. GOV_SAFE inherits PROPOSER, EXECUTOR
      // and CANCELLER, so a single key would own governance outright, and every Step 10 assertion still
      // passes because they only check that the DEPLOYER holds nothing.
      if (!relaxLocalRules) {
        throw new Error(
          `${label} ${addr} has no code on network ${network.name}; it must be a deployed multisig contract.`,
        );
      }
      console.log(
        `  WARNING: ${label} ${addr} has no code; accepted only on ${network.name}.`,
      );
    }
  }
  if (safeOwnerships.length === 2) {
    const [gov, guardian] = safeOwnerships;
    const shared = assertSafeOwnersDisjoint(rulesChainId, gov, guardian);
    if (shared.length > 0) {
      console.log(
        `  WARNING: GUARDIAN_SAFE shares owner(s) ${shared.join(", ")} with GOV_SAFE; accepted only on test ` +
          `chain ${chainId}.`,
      );
    } else {
      console.log(
        `  Safe owners disjoint: Gov ${gov.threshold}-of-${gov.owners.length}, Guardian ` +
          `${guardian.threshold}-of-${guardian.owners.length}`,
      );
    }
  } else {
    console.log(
      "  WARNING: Safe owner disjointness not checked; both Safes must be deployed contracts to read owners.",
    );
  }
  if (stakingToken === null && !relaxLocalRules) {
    // MockERC20 has an unpermissioned public mint, and NoxRegistry writes the staking token only in
    // initialize with no setter, so falling back to it off local permanently binds stake economics to a
    // token anyone can print. Fail closed rather than deploy one.
    throw new Error(
      `STAKING_TOKEN is required on network ${network.name}: the MockERC20 fallback has an open mint ` +
        `and NoxRegistry cannot be repointed after initialize.`,
    );
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
  const stakingDecimals =
    stakingToken === null
      ? DEV_STAKING_TOKEN_DECIMALS
      : await tokenDecimals("STAKING_TOKEN", stakingToken);
  if (stakingToken !== null) {
    assertStakingToken(rulesChainId, stakingToken, stakingDecimals);
    if (explicitFeeAssets !== null) {
      assertFeeAssets(rulesChainId, explicitFeeAssets, stakingToken);
    }
  }
  const { minStake, minStakeFloor } = stakeAmounts(
    rulesChainId,
    stakingDecimals,
  );
  let kageParams: {
    token: string | null;
    decimals: bigint;
    minStake: bigint;
    minStakeFloor: bigint;
    exitDelay: bigint;
  } | null = null;
  if (kageEnabled) {
    const kageToken = optionalAddress("KAGE_STAKING_TOKEN");
    if (kageToken === null && !relaxLocalRules) {
      throw new Error(
        `KAGE_STAKING_TOKEN is required with KAGE_MODULE=on on network ${network.name}; it is written once in ` +
          "KageRegistry.initialize.",
      );
    }
    if (
      kageToken !== null &&
      (await ethers.provider.getCode(kageToken)) === "0x"
    ) {
      throw new Error(
        `KAGE_STAKING_TOKEN ${kageToken} has no deployed code on network ${network.name}.`,
      );
    }
    const decimals =
      kageToken === null
        ? stakingDecimals
        : await tokenDecimals("KAGE_STAKING_TOKEN", kageToken);
    assertStakingToken(rulesChainId, kageToken ?? ethers.ZeroAddress, decimals);
    kageParams = {
      token: kageToken,
      decimals,
      ...stakeAmounts(rulesChainId, decimals, "KAGE_"),
      exitDelay: kageExitDelay(),
    };
  }
  console.log(
    `  Staking token decimals: ${stakingDecimals}; min stake ${ethers.formatUnits(minStake, stakingDecimals)}, ` +
      `floor ${ethers.formatUnits(minStakeFloor, stakingDecimals)}`,
  );
  console.log(
    multisigVerifiers === "stub"
      ? "  Multisig verifier slots: stub (multisig actions and multisig Nox fees revert until the Timelock sets the real verifiers)"
      : "  Multisig verifier slots: real",
  );
  console.log(`  Kage module: ${kageEnabled ? "on" : "off"}`);
  console.log();

  const startBlock = await ethers.provider.getBlockNumber();
  const startTime = new Date().toISOString();

  const baseName = deploymentBaseName(network.name);
  const deployDir =
    process.env.DEPLOYMENTS_DIR ?? path.join(__dirname, "../deployments");
  fs.mkdirSync(deployDir, { recursive: true });
  const deployFile = path.join(deployDir, `${baseName}.json`);
  const latestFile = path.join(deployDir, `${network.name}-latest.json`);
  assertNoPriorDeployment(latestFile, isLocal);
  const secretsFile = path.join(deployDir, `${baseName}.secrets.json`);
  // writeRecord creates this run's record exclusively on its first call and refreshes the same file after.
  let recordCreated = false;
  for (const file of [deployFile, secretsFile]) {
    if (fs.existsSync(file)) {
      throw new Error(
        `${file} already exists before any transaction; refusing to overwrite another deployment's file.`,
      );
    }
  }

  console.log(`Step 0: ${COMPLIANCE_SOURCE_LABELS[compliance.source]}.`);

  // Written to disk BEFORE any transaction. A generated secret that exists only in memory is lost to
  // any throw after the first deploy, and by then the pool is deployed and bound to its public key, so
  // every note encrypted to it would be permanently undecryptable. The file is gitignored alongside the
  // record and is owner-read-only.
  if (compliance.source === "generated" && compliance.sk !== null) {
    writeNewFile(
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
      0o600,
    );
    console.log(`  Compliance secret written to ${secretsFile}`);
  }
  console.log(`  Compliance PK: (${compliance.pk[0]}, ${compliance.pk[1]})`);
  console.log();

  const slotSpecs = CIRCUIT_VERIFIERS.map((spec, circuitId) =>
    multisigVerifiers === "stub" && MULTISIG_CIRCUIT_IDS.has(circuitId)
      ? REVERTING_VERIFIER
      : spec,
  );
  const deployedSpecs = [...new Set([...slotSpecs, KAGE_VERIFIER])];
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
      sha256File(path.join(circuitsDir, `${name}.json`), !relaxLocalRules),
    ]),
  );
  const vkHashes: Record<string, string> = {};
  for (const spec of deployedSpecs) {
    const vkHash = verifierVkHash(spec.source);
    if (vkHash !== null) vkHashes[verifierName(spec)] = vkHash;
  }
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
  const verifierAddresses = new Map<VerifierSpec, string>();
  for (const spec of deployedSpecs) {
    verifierAddresses.set(spec, await deployVerifier(spec));
  }
  const slotAddresses = slotSpecs.map((spec) =>
    requireDeployed(verifierAddresses, spec),
  );
  const kageVerifierAddr = requireDeployed(verifierAddresses, KAGE_VERIFIER);
  console.log();

  console.log("Step 3: Staking token...");
  let stakingTokenAddr: string;
  if (stakingToken !== null) {
    stakingTokenAddr = stakingToken;
    console.log(`  Using supplied staking token: ${stakingTokenAddr}`);
  } else {
    const token = await (
      await ethers.getContractFactory("MockERC20")
    ).deploy("NOX Stake Token", "NOX-STK", DEV_STAKING_TOKEN_DECIMALS);
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
        minStake,
        UNSTAKE_DELAY,
        minStakeFloor,
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
        ...slotAddresses,
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

  const howlPaymentAdapterFactory =
    await ethers.getContractFactory("HowlPaymentAdapter");
  const howlPaymentAdapter = await howlPaymentAdapterFactory.deploy(
    darkPoolAddr,
    noxEntryPointAddr,
    false,
  );
  await howlPaymentAdapter.waitForDeployment();
  const howlPaymentAdapterAddr = await howlPaymentAdapter.getAddress();
  const howlMultisigPaymentAdapter = await howlPaymentAdapterFactory.deploy(
    darkPoolAddr,
    noxEntryPointAddr,
    true,
  );
  await howlMultisigPaymentAdapter.waitForDeployment();
  const howlMultisigPaymentAdapterAddr =
    await howlMultisigPaymentAdapter.getAddress();

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
  console.log(
    `  HowlPaymentAdapter (multisig): ${howlMultisigPaymentAdapterAddr}`,
  );
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

  let kage: {
    registry: string;
    settlement: string;
    stakingToken: string;
    params: NonNullable<typeof kageParams>;
    registryContract: BaseContract;
    settlementContract: BaseContract;
  } | null = null;
  if (kageParams !== null) {
    console.log("Step 7c: Kage settlement module...");
    const kageStakingToken = kageParams.token ?? stakingTokenAddr;
    const registryContract = await upgrades.deployProxy(
      await ethers.getContractFactory("KageRegistry"),
      [
        {
          initialAdminDelay: adminTransferDelay,
          initialAdmin: timelockAddr,
          stakingToken: kageStakingToken,
          minStake: kageParams.minStake,
          minStakeFloor: kageParams.minStakeFloor,
          exitDelay: kageParams.exitDelay,
          slasher: guardianSafe,
          configManager: timelockAddr,
          upgrader: timelockAddr,
        },
      ],
      { kind: "uups", initializer: "initialize" },
    );
    await registryContract.waitForDeployment();
    const registry = await registryContract.getAddress();
    const settlementContract = await (
      await ethers.getContractFactory("KageSettlement")
    ).deploy(darkPoolAddr, registry);
    await settlementContract.waitForDeployment();
    const settlement = await settlementContract.getAddress();
    kage = {
      registry,
      settlement,
      stakingToken: kageStakingToken,
      params: kageParams,
      registryContract,
      settlementContract,
    };
    console.log(`  KageRegistry: ${registry}`);
    console.log(`  KageSettlement: ${settlement}`);
    console.log();
  }

  const recordedCoreContracts = {
    poseidon2: poseidon2Addr,
    ...Object.fromEntries(
      CIRCUIT_VERIFIERS.map((spec, circuitId) => [
        spec.key,
        slotAddresses[circuitId],
      ]),
    ),
    ...(multisigVerifiers === "stub"
      ? {
          [REVERTING_VERIFIER.key]: requireDeployed(
            verifierAddresses,
            REVERTING_VERIFIER,
          ),
        }
      : {}),
    kageVerifier: kageVerifierAddr,
    complianceRegistry: complianceRegistryAddr,
    noxRegistry: noxRegistryAddr,
    noxRewardPool: rewardPoolAddr,
    noxSandboxImplementation: sandboxImplementationAddr,
    noxEntryPoint: noxEntryPointAddr,
    howlPaymentAdapter: howlPaymentAdapterAddr,
    howlMultisigPaymentAdapter: howlMultisigPaymentAdapterAddr,
    bundleExecutor: bundleExecutorAddr,
    darkPool: darkPoolAddr,
    stakingToken: stakingTokenAddr,
    ...(kage === null
      ? {}
      : { kageRegistry: kage.registry, kageSettlement: kage.settlement }),
  };
  const proxies: [string, string][] = [
    ["darkPool", darkPoolAddr],
    ["noxRegistry", noxRegistryAddr],
    ["noxRewardPool", rewardPoolAddr],
    ...(kage === null
      ? []
      : [["kageRegistry", kage.registry] as [string, string]]),
  ];
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
  // A verifier's identity is its runtime code hash, which every proving backend and the stub have; VK_HASH stays
  // Honk metadata.
  const verifierSlots = slotSpecs.map((spec, circuitId) => ({
    circuitId,
    verifier: verifierName(spec),
    address: slotAddresses[circuitId],
    codeHash: coreContractCodeHashes[CIRCUIT_VERIFIERS[circuitId].key],
    vkHash: vkHashes[verifierName(spec)] ?? null,
  }));
  const proxySlots: Record<string, { impl: string; admin: string }> = {};
  const proxyImplementationCodeHashes: Record<string, string> = {};
  for (const [name, address] of proxies) {
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

  // The module is registered by the Timelock (UPGRADER_ROLE), so the deploy records the exact call;
  // scripts/check-kage-module.ts checks the scheduled call before execution and the registered module after it.
  const kageRecord =
    kage === null
      ? null
      : {
          registry: kage.registry,
          settlement: kage.settlement,
          verifier: kageVerifierAddr,
          stakingToken: kage.stakingToken,
          stakingTokenDecimals: Number(kage.params.decimals),
          minStake: kage.params.minStake.toString(),
          minStakeFloor: kage.params.minStakeFloor.toString(),
          exitDelaySeconds: Number(kage.params.exitDelay),
          eip712Domain: {
            name: "HisokaKageSettlement",
            version: "1",
            chainId: Number(chainId),
            verifyingContract: kage.settlement,
          },
          settlementTypehash: String(
            await kage.settlementContract.getFunction("SETTLEMENT_TYPEHASH")(),
          ),
          moduleLayout: Object.fromEntries(
            Object.entries(KAGE_MODULE_LAYOUT).map(([k, v]) => [k, Number(v)]),
          ),
          moduleRegistration: kageModuleRegistration(
            darkPoolAddr,
            kage.settlement,
            kageVerifierAddr,
          ),
        };

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
        (await howlPaymentAdapter.ENTRY_POINT()) === noxEntryPointAddr &&
        !(await howlPaymentAdapter.MULTISIG()),
    },
    {
      label:
        "Multisig HowlPaymentAdapter is linked to DarkPool and NoxEntryPoint and pulls through withdrawMultisig",
      ok:
        (await howlMultisigPaymentAdapter.DARK_POOL()) === darkPoolAddr &&
        (await howlMultisigPaymentAdapter.ENTRY_POINT()) ===
          noxEntryPointAddr &&
        (await howlMultisigPaymentAdapter.MULTISIG()),
    },
    {
      label: `Every circuit slot holds its intended verifier (multisig slots: ${multisigVerifiers})`,
      ok: (
        await Promise.all(
          slotAddresses.map(
            async (address, circuitId) =>
              (await darkPool.verifier(circuitId)) === address,
          ),
        )
      ).every(Boolean),
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
  if (kage !== null) {
    const registry = kage.registryContract;
    const settlement = kage.settlementContract;
    const read = (contract: BaseContract, fn: string): Promise<unknown> =>
      contract.getFunction(fn)();
    wiring.push(
      {
        label: "KageSettlement is linked to DarkPool and KageRegistry",
        ok:
          (await read(settlement, "DARK_POOL")) === darkPoolAddr &&
          (await read(settlement, "REGISTRY")) === kage.registry,
      },
      {
        label: `KageRegistry stakes ${kage.stakingToken} (${kage.params.decimals} decimals): min ${kage.params.minStake}, floor ${kage.params.minStakeFloor}, exit delay ${kage.params.exitDelay}s`,
        ok:
          (await read(registry, "stakingToken")) === kage.stakingToken &&
          (await read(registry, "minStake")) === kage.params.minStake &&
          (await read(registry, "minStakeFloor")) ===
            kage.params.minStakeFloor &&
          (await read(registry, "exitDelay")) === kage.params.exitDelay,
      },
      {
        label: `KageRegistry DEFAULT_ADMIN is the Timelock with a ${adminTransferDelay}s transfer delay`,
        ok:
          (await read(registry, "defaultAdmin")) === timelockAddr &&
          (await read(registry, "defaultAdminDelay")) === adminTransferDelay,
      },
    );
  }
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
  const roleTables: {
    label: string;
    contract: BaseContract;
    roles: RoleExpectation[];
  }[] = [
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
  if (kage !== null) {
    const registry = kage.registryContract;
    const role = async (name: string): Promise<string> =>
      String(await registry.getFunction(name)());
    roleTables.push({
      label: "KageRegistry",
      contract: registry,
      roles: [
        {
          name: "SLASHER_ROLE",
          role: await role("SLASHER_ROLE"),
          holders: [guardianSafe],
        },
        {
          name: "CONFIG_ROLE",
          role: await role("CONFIG_ROLE"),
          holders: [timelockAddr],
        },
        {
          name: "UPGRADER_ROLE",
          role: await role("UPGRADER_ROLE"),
          holders: [timelockAddr],
        },
      ],
    });
  }
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
    for (const [name, address] of proxies) {
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
    kage === null
      ? "Timelock, DarkPool, NoxRegistry, NoxRewardPool and ComplianceRegistry"
      : "Timelock, DarkPool, NoxRegistry, NoxRewardPool, ComplianceRegistry and KageRegistry";
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
    proxies.map(([, address]) => address),
    !relaxLocalRules,
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
    for (const [spec, address] of verifierAddresses) {
      await tryVerify(address, [], `${spec.source}:${spec.contract}`);
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
    await tryVerify(howlPaymentAdapterAddr, [
      darkPoolAddr,
      noxEntryPointAddr,
      false,
    ]);
    await tryVerify(howlMultisigPaymentAdapterAddr, [
      darkPoolAddr,
      noxEntryPointAddr,
      true,
    ]);
    await tryVerify(bundleExecutorAddr, [darkPoolAddr]);
    if (kage !== null) {
      await tryVerify(kage.settlement, [darkPoolAddr, kage.registry]);
    }
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
        safeOwners: Object.fromEntries(
          safeOwnerships.map((safe) => [
            safe.label,
            { owners: safe.owners, threshold: Number(safe.threshold) },
          ]),
        ),
      },
      compliance: {
        source: compliance.source,
        publicKeyX: compliance.pk[0].toString(),
        publicKeyY: compliance.pk[1].toString(),
      },
      contracts: deployedContracts,
      constructorArgs: {
        noxSandboxImplementation: [],
        noxEntryPoint: [rewardPoolAddr, sandboxImplementationAddr],
        howlPaymentAdapter: [darkPoolAddr, noxEntryPointAddr, false],
        howlMultisigPaymentAdapter: [darkPoolAddr, noxEntryPointAddr, true],
        bundleExecutor: [darkPoolAddr],
        complianceRegistry: [
          timelockAddr,
          committeeThreshold.toString(),
          committeeSize.toString(),
        ],
        ...(kage === null
          ? {}
          : { kageSettlement: [darkPoolAddr, kage.registry] }),
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
      staking: {
        token: stakingTokenAddr,
        decimals: Number(stakingDecimals),
        minStake: minStake.toString(),
        minStakeFloor: minStakeFloor.toString(),
      },
      multisigVerifiers,
      verifierSlots,
      kage: kageRecord,
    };
  }

  async function writeRecord(latest: boolean): Promise<string> {
    const record = buildRecord(await ethers.provider.getBlockNumber());
    const json = JSON.stringify(record, null, 2);
    if (recordCreated) fs.writeFileSync(deployFile, json);
    else writeNewFile(deployFile, json);
    recordCreated = true;
    if (latest) fs.writeFileSync(latestFile, json);
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
  console.log(`  Howl Multisig Adapter: ${howlMultisigPaymentAdapterAddr}`);
  console.log(`  BundleExecutor:${bundleExecutorAddr}`);
  console.log(`  Staking Token: ${stakingTokenAddr}`);
  if (adaptorAddr) console.log(`  UniswapAdaptor:${adaptorAddr}`);
  if (kageRecord !== null) {
    console.log(`  KageRegistry:  ${kageRecord.registry}`);
    console.log(`  KageSettlement:${kageRecord.settlement}`);
    console.log(
      `  Kage module registration (Timelock call; once scheduled run scripts/check-kage-module.ts with ` +
        `KAGE_OPERATION_ID=<operation id>, and again without it after execution): target ` +
        `${kageRecord.moduleRegistration.target} data ${kageRecord.moduleRegistration.data}`,
    );
  }
  console.log();

  if (isLocal) {
    console.log("Local ephemeral deployment; no private backup is required.");
  } else {
    console.log("REQUIRED BACKUP - push these to the private backup repo now:");
    console.log(
      `  - ${deployFile} (addresses, proxy slots, circuit hashes, VK hashes, storage manifest)`,
    );
    if (compliance.source === "generated") {
      console.log(
        `  - ${secretsFile} (COMPLIANCE SECRET KEY, written before any transaction, mode 0600)`,
      );
      console.log(
        "    Move it into the secrets vault and remove the local copy. Losing it makes every note",
      );
      console.log(
        "    encrypted to the compliance key permanently undecryptable.",
      );
    } else if (compliance.source === "supplied-secret") {
      console.log(
        "  - COMPLIANCE_SECRET_KEY was supplied via env; ensure it is already backed up.",
      );
    } else {
      console.log(
        "  - The compliance key was supplied as a public key; its secret shares stay with the committee.",
      );
    }
    console.log();
    console.log("The deployment is not done until the backup is pushed.");
  }

  return {
    deployment: buildRecord(await ethers.provider.getBlockNumber()),
    deployFile,
    secretsFile: compliance.source === "generated" ? secretsFile : null,
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
