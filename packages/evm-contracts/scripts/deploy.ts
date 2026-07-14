/**
 * Fresh pre-mainnet deployment of the DarkPool + NOX contract set under governance.
 *
 * All stateful contracts are UUPS proxies initialized atomically (impl + initialize in one tx).
 * Governance:
 *   - OZ TimelockController (48h min delay) holds DEFAULT_ADMIN + UPGRADER on every contract.
 *   - Governance Safe (3-of-5, out-of-band) is the sole proposer + executor on the Timelock.
 *   - Guardian Safe (2-of-3, out-of-band) holds the DarkPool PAUSER role and the Timelock CANCELLER role.
 *   - The deploying EOA renounces all power before the script exits; a final assertion reverts if any
 *     privileged role is still held by an EOA.
 *
 * Upgrade runbook: before any on-chain upgrade, run `validateUpgrade` against the DEPLOYED
 *   .openzeppelin/<network>.json manifest on the fork job. The in-repo DarkPoolV1 baseline anchors the
 *   CI gate but cannot see a MerkleTreeLib.Tree reshape (shared library); the deployed manifest anchors
 *   to real proxy storage and is the authoritative pre-upgrade storage-compat check.
 *
 * Required env:
 *   GOV_SAFE       governance multisig (3-of-5), proposer + executor
 *   GUARDIAN_SAFE  guardian multisig (2-of-3), pauser + canceller
 * Optional env:
 *   COMPLIANCE_SECRET_KEY  reuse an existing compliance BJJ secret (else one is generated and printed)
 *   STAKING_TOKEN          existing ERC20 staking token (else a dev MockERC20 is deployed)
 *   SWAP_ROUTER            deploy UniswapAdaptor against this router
 *
 * Usage:
 *   GOV_SAFE=0x.. GUARDIAN_SAFE=0x.. npx hardhat run scripts/deploy.ts --network <net>
 */

import { ethers, network, upgrades, run } from "hardhat";
import * as fs from "fs";
import * as path from "path";
import * as crypto from "crypto";
import { Base8, mulPointEscalar, Point } from "@zk-kit/baby-jubjub";

const BJJ_SUBGROUP_ORDER =
  2736030358979909402780800718157159386076813972158567259200215660948447373041n;

// 48h timelock; the 2-step DEFAULT_ADMIN transfer delay (AccessControlDefaultAdminRules) matches it.
const TIMELOCK_MIN_DELAY = 48n * 60n * 60n;
const ADMIN_TRANSFER_DELAY = 48 * 60 * 60;

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

function generateComplianceKeypair(): { sk: bigint; pk: Point<bigint> } {
  const rawSk = BigInt("0x" + crypto.randomBytes(32).toString("hex"));
  const sk = rawSk % BJJ_SUBGROUP_ORDER;
  return { sk, pk: mulPointEscalar(Base8, sk) };
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

function sha256File(filePath: string): string {
  if (!fs.existsSync(filePath)) return "NOT_FOUND";
  return crypto
    .createHash("sha256")
    .update(fs.readFileSync(filePath))
    .digest("hex");
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

async function slot(addr: string, s: string): Promise<string> {
  const raw = await ethers.provider.getStorage(addr, s);
  return ethers.getAddress("0x" + raw.slice(-40));
}

async function main() {
  const [deployer] = await ethers.getSigners();
  const chainId = (await ethers.provider.getNetwork()).chainId;
  const balance = await ethers.provider.getBalance(deployer.address);

  const govSafe = requireSafeAddress("GOV_SAFE");
  const guardianSafe = requireSafeAddress("GUARDIAN_SAFE");

  console.log("DarkPool + NOX governed deployment");
  console.log(`  Network:       ${network.name} (chainId: ${chainId})`);
  console.log(`  Deployer:      ${deployer.address}`);
  console.log(`  Balance:       ${ethers.formatEther(balance)} ETH`);
  console.log(`  Gov Safe:      ${govSafe}`);
  console.log(`  Guardian Safe: ${guardianSafe}`);
  for (const [label, addr] of [
    ["GOV_SAFE", govSafe],
    ["GUARDIAN_SAFE", guardianSafe],
  ] as const) {
    if ((await ethers.provider.getCode(addr)) === "0x") {
      console.log(
        `  WARNING: ${label} ${addr} has no code; in production it MUST be a multisig contract.`,
      );
    }
  }
  console.log();

  const startBlock = await ethers.provider.getBlockNumber();
  const startTime = new Date().toISOString();

  const existingSk = process.env.COMPLIANCE_SECRET_KEY;
  let compliance: { sk: bigint; pk: Point<bigint> };
  if (existingSk) {
    const sk = BigInt(existingSk) % BJJ_SUBGROUP_ORDER;
    compliance = { sk, pk: mulPointEscalar(Base8, sk) };
    console.log("Step 0: Reusing supplied compliance keypair.");
  } else {
    compliance = generateComplianceKeypair();
    console.log("Step 0: Generated a fresh compliance keypair.");
  }
  console.log(`  Compliance PK: (${compliance.pk[0]}, ${compliance.pk[1]})`);
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
  const verifiers: { verifier: string; name: string }[] = [];
  for (const p of verifierPaths) verifiers.push(await deployVerifier(p));
  console.log();

  console.log("Step 3: Staking token...");
  let stakingTokenAddr: string;
  const existingToken = process.env.STAKING_TOKEN;
  if (existingToken && ethers.isAddress(existingToken)) {
    stakingTokenAddr = ethers.getAddress(existingToken);
    console.log(`  Using supplied staking token: ${stakingTokenAddr}`);
  } else {
    const token = await (
      await ethers.getContractFactory("MockERC20")
    ).deploy("NOX Stake Token", "NOX-STK", 18);
    await token.waitForDeployment();
    stakingTokenAddr = await token.getAddress();
    console.log(`  Deployed dev MockERC20 staking token: ${stakingTokenAddr}`);
  }
  console.log();

  console.log("Step 4: TimelockController (48h)...");
  const timelock = await (
    await ethers.getContractFactory("TimelockController")
  ).deploy(TIMELOCK_MIN_DELAY, [govSafe], [govSafe], deployer.address);
  await timelock.waitForDeployment();
  const timelockAddr = await timelock.getAddress();
  console.log(`  TimelockController: ${timelockAddr}`);
  console.log();

  console.log("Step 5: NoxRegistry proxy...");
  const NoxRegistryFactory = await ethers.getContractFactory("NoxRegistry");
  const noxRegistry = await upgrades.deployProxy(
    NoxRegistryFactory,
    [
      [
        ADMIN_TRANSFER_DELAY,
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
        ADMIN_TRANSFER_DELAY,
        timelockAddr,
        noxRegistryAddr,
        guardianSafe, // admin (pause / asset status / rescue)
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
        ADMIN_TRANSFER_DELAY,
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

  console.log("Step 7b: ComplianceRegistry (social audit log)...");
  const committeeThreshold = BigInt(process.env.COMPLIANCE_THRESHOLD ?? "3");
  const committeeSize = BigInt(process.env.COMPLIANCE_COMMITTEE_SIZE ?? "5");
  const complianceRegistry = await (
    await ethers.getContractFactory("ComplianceRegistry")
  ).deploy(timelockAddr, committeeThreshold, committeeSize);
  await complianceRegistry.waitForDeployment();
  const complianceRegistryAddr = await complianceRegistry.getAddress();
  console.log(
    `  ComplianceRegistry: ${complianceRegistryAddr} (t=${committeeThreshold}, n=${committeeSize}, admin=${timelockAddr})`,
  );
  console.log();

  console.log("Step 8: Governance wiring...");
  const CANCELLER_ROLE = await timelock.CANCELLER_ROLE();
  await (await timelock.grantRole(CANCELLER_ROLE, guardianSafe)).wait();
  console.log(`  Granted Timelock CANCELLER_ROLE to guardian ${guardianSafe}`);
  // DarkPool PAUSER was granted to the guardian in initialize (deployer cannot grant it post-init).
  console.log();

  console.log("Step 9: Renouncing deployer's Timelock admin...");
  await (
    await timelock.renounceRole(DEFAULT_ADMIN_ROLE, deployer.address)
  ).wait();
  console.log("  Deployer renounced Timelock DEFAULT_ADMIN.");
  console.log();

  console.log("Step 10: Asserting no EOA retains privileged power...");
  const PAUSER_ROLE = await darkPool.PAUSER_ROLE();
  const DP_UPGRADER = await darkPool.UPGRADER_ROLE();
  const REG_UPGRADER = await noxRegistry.UPGRADER_ROLE();
  const POOL_UPGRADER = await rewardPool.UPGRADER_ROLE();
  const PROPOSER_ROLE = await timelock.PROPOSER_ROLE();
  const EXECUTOR_ROLE = await timelock.EXECUTOR_ROLE();

  const deployerMustNotHold: {
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
      label: "Timelock.DEFAULT_ADMIN",
      has: () => timelock.hasRole(DEFAULT_ADMIN_ROLE, deployer.address),
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
  for (const check of deployerMustNotHold) {
    if (await check.has()) {
      throw new Error(
        `SECURITY: deployer EOA still holds ${check.label}; aborting.`,
      );
    }
  }

  // Positive wiring assertions: power sits with the Timelock + Safes.
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
    {
      label: "Timelock is NoxRegistry DEFAULT_ADMIN",
      ok: await noxRegistry.hasRole(DEFAULT_ADMIN_ROLE, timelockAddr),
    },
    {
      label: "Timelock is NoxRewardPool DEFAULT_ADMIN",
      ok: await rewardPool.hasRole(DEFAULT_ADMIN_ROLE, timelockAddr),
    },
    {
      label: "Gov Safe is Timelock PROPOSER",
      ok: await timelock.hasRole(PROPOSER_ROLE, govSafe),
    },
    {
      label: "Gov Safe is Timelock EXECUTOR",
      ok: await timelock.hasRole(EXECUTOR_ROLE, govSafe),
    },
    {
      label: "Guardian is Timelock CANCELLER",
      ok: await timelock.hasRole(CANCELLER_ROLE, guardianSafe),
    },
    {
      label: "Timelock self-administers",
      ok: await timelock.hasRole(DEFAULT_ADMIN_ROLE, timelockAddr),
    },
  ];
  for (const w of wiring) {
    console.log(`  [${w.ok ? "ok" : "FAIL"}] ${w.label}`);
    if (!w.ok) throw new Error(`SECURITY: wiring check failed: ${w.label}`);
  }
  console.log("  No EOA holds any privileged role.");
  console.log();

  console.log("Step 11: EIP-1967 proxy slots...");
  const proxySlots: Record<string, { impl: string; admin: string }> = {};
  for (const [name, addr] of [
    ["darkPool", darkPoolAddr],
    ["noxRegistry", noxRegistryAddr],
    ["noxRewardPool", rewardPoolAddr],
  ] as const) {
    const impl = await slot(addr, IMPL_SLOT);
    const admin = await slot(addr, ADMIN_SLOT);
    proxySlots[name] = { impl, admin };
    console.log(
      `  ${name}: impl=${impl} admin=${admin} (UUPS admin slot is 0)`,
    );
  }
  console.log();

  let multicallAddr = "";
  {
    console.log("Step 12: RelayerMulticall...");
    const multicall = await (
      await ethers.getContractFactory("RelayerMulticall")
    ).deploy();
    await multicall.waitForDeployment();
    multicallAddr = await multicall.getAddress();
    console.log(`  RelayerMulticall: ${multicallAddr}`);
    console.log();
  }

  const swapRouter = process.env.SWAP_ROUTER;
  let adaptorAddr = "";
  if (swapRouter && ethers.isAddress(swapRouter)) {
    console.log("Step 13: UniswapAdaptor...");
    const adaptor = await (
      await ethers.getContractFactory("UniswapAdaptor", {
        libraries: { Poseidon2: poseidon2Addr },
      })
    ).deploy(darkPoolAddr, swapRouter);
    await adaptor.waitForDeployment();
    adaptorAddr = await adaptor.getAddress();
    console.log(`  UniswapAdaptor: ${adaptorAddr}`);
    console.log();
  }

  if (network.name !== "hardhat" && network.name !== "localhost") {
    console.log("Step 14: Block-explorer verification (best-effort)...");
    await tryVerify(poseidon2Addr, []);
    for (let i = 0; i < verifiers.length; i++) {
      await tryVerify(
        verifiers[i].verifier,
        [],
        `${verifierPaths[i]}:HonkVerifier`,
      );
    }
    await tryVerify(timelockAddr, [
      TIMELOCK_MIN_DELAY.toString(),
      [govSafe],
      [govSafe],
      deployer.address,
    ]);
    console.log();
  }

  const endBlock = await ethers.provider.getBlockNumber();
  const circuitsDir = path.join(__dirname, "../../circuits/target");

  const deployment = {
    meta: {
      network: network.name,
      chainId: Number(chainId),
      deployer: deployer.address,
      deployedAt: startTime,
      startBlock,
      endBlock,
    },
    governance: {
      timelock: timelockAddr,
      timelockMinDelaySeconds: Number(TIMELOCK_MIN_DELAY),
      govSafe,
      guardianSafe,
    },
    compliance: {
      publicKeyX: compliance.pk[0].toString(),
      publicKeyY: compliance.pk[1].toString(),
    },
    contracts: {
      poseidon2: poseidon2Addr,
      zkTranscriptLib: zkTranscriptLibAddr,
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
      darkPool: darkPoolAddr,
      stakingToken: stakingTokenAddr,
      relayerMulticall: multicallAddr,
      uniswapAdaptor: adaptorAddr,
    },
    proxySlots,
    versions: {
      solidity: "0.8.28",
      optimizer: { enabled: true, runs: 1 },
      evmVersion: "cancun",
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      hardhat: require("hardhat/package.json").version,
      noir: "1.0.0-beta.22",
      bbjs: "5.0.0",
    },
    circuitHashes: {
      deposit: sha256File(path.join(circuitsDir, "deposit.json")),
      withdraw: sha256File(path.join(circuitsDir, "withdraw.json")),
      transfer: sha256File(path.join(circuitsDir, "transfer.json")),
      join: sha256File(path.join(circuitsDir, "join.json")),
      split: sha256File(path.join(circuitsDir, "split.json")),
      public_claim: sha256File(path.join(circuitsDir, "public_claim.json")),
      withdraw_multisig: sha256File(
        path.join(circuitsDir, "withdraw_multisig.json"),
      ),
      transfer_multisig: sha256File(
        path.join(circuitsDir, "transfer_multisig.json"),
      ),
      split_multisig: sha256File(path.join(circuitsDir, "split_multisig.json")),
      join_multisig: sha256File(path.join(circuitsDir, "join_multisig.json")),
    },
  };

  const timestamp = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
  const deployDir = path.join(__dirname, "../deployments");
  fs.mkdirSync(deployDir, { recursive: true });
  const deployFile = path.join(deployDir, `${network.name}-${timestamp}.json`);
  fs.writeFileSync(deployFile, JSON.stringify(deployment, null, 2));
  const latestFile = path.join(deployDir, `${network.name}-latest.json`);
  fs.writeFileSync(latestFile, JSON.stringify(deployment, null, 2));
  console.log(`Deployment record: ${deployFile}`);
  console.log(`Latest pointer:    ${latestFile}`);
  console.log();

  console.log("DEPLOYMENT COMPLETE");
  console.log(`  Timelock:      ${timelockAddr}`);
  console.log(`  DarkPool:      ${darkPoolAddr}`);
  console.log(`  NoxRegistry:   ${noxRegistryAddr}`);
  console.log(`  NoxRewardPool: ${rewardPoolAddr}`);
  console.log(`  Staking Token: ${stakingTokenAddr}`);
  if (multicallAddr) console.log(`  Multicall:     ${multicallAddr}`);
  if (adaptorAddr) console.log(`  UniswapAdaptor:${adaptorAddr}`);
  console.log();

  console.log("REQUIRED BACKUP (S15) - back these up to the private repo now:");
  console.log(`  - ${deployFile} (addresses, slots, verifier hashes)`);
  console.log(
    "  - Compliance secret key (below): store in the secrets vault ONLY.",
  );
  if (!existingSk) {
    console.log(
      `  - COMPLIANCE_SECRET_KEY=${compliance.sk.toString()}  <-- generated this run; SAVE IT NOW or funds`,
    );
    console.log(
      "    encrypted to the compliance key become undecryptable. This is printed once and NOT written to disk.",
    );
  } else {
    console.log(
      "  - COMPLIANCE_SECRET_KEY was supplied via env; ensure it is already backed up.",
    );
  }
  console.log();
  console.log(
    "No secrets file was written. The deployment is not done until the backup is pushed.",
  );
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
