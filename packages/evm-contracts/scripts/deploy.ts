/**
 * Post-deploy setup:
 *   - Whitelist staking token in NoxRewardPool
 *
 * Usage:
 *   npx hardhat run scripts/deploy.ts --network arbitrumSepolia
 *   npx hardhat run scripts/deploy.ts --network hardhat  (local test)
 *
 * Outputs:
 *   deployments/<network>-<timestamp>.json
 */

import { ethers, network, run } from "hardhat";
import * as fs from "fs";
import * as path from "path";
import * as crypto from "crypto";
import { Base8, mulPointEscalar, Point } from "@zk-kit/baby-jubjub";

// BabyJubJub subgroup order
const BJJ_SUBGROUP_ORDER =
  2736030358979909402780800718157159386076813972158567259200215660948447373041n;

function generateComplianceKeypair(): {
  sk: bigint;
  pk: Point<bigint>;
} {
  const randomBytes = crypto.randomBytes(32);
  const rawSk = BigInt("0x" + randomBytes.toString("hex"));
  const sk = rawSk % BJJ_SUBGROUP_ORDER;
  const pk = mulPointEscalar(Base8, sk);

  return { sk, pk };
}

async function deployVerifier(contractPath: string): Promise<{
  verifier: string;
  name: string;
}> {
  const name =
    contractPath.split("/").pop()?.replace(".sol", "") || contractPath;
  console.log(`  Deploying ${name}...`);

  // TranscriptLib is inlined (internal functions) — no separate deployment needed
  const VerifierFactory = await ethers.getContractFactory(
    `${contractPath}:HonkVerifier`,
  );
  const verifier = await VerifierFactory.deploy();
  await verifier.waitForDeployment();
  const verifierAddr = await verifier.getAddress();
  console.log(`    HonkVerifier: ${verifierAddr}`);

  return { verifier: verifierAddr, name };
}

function sha256File(filePath: string): string {
  if (!fs.existsSync(filePath)) return "NOT_FOUND";
  const content = fs.readFileSync(filePath);
  return crypto.createHash("sha256").update(content).digest("hex");
}

async function tryVerify(
  address: string,
  constructorArgs: any[],
  contract?: string,
): Promise<boolean> {
  if (network.name === "hardhat" || network.name === "localhost") {
    return false;
  }

  try {
    console.log(`  Verifying ${address} on ${network.name}...`);
    await run("verify:verify", {
      address,
      constructorArguments: constructorArgs,
      contract,
    });
    console.log(`  Verified!`);
    return true;
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    if (msg.includes("Already Verified")) {
      console.log(`  Already verified.`);
      return true;
    }
    console.log(`  Verification failed: ${msg}`);
    return false;
  }
}

async function main() {
  const [deployer] = await ethers.getSigners();
  const chainId = (await ethers.provider.getNetwork()).chainId;
  const balance = await ethers.provider.getBalance(deployer.address);

  console.log("╔══════════════════════════════════════════════════════╗");
  console.log("║  NOX PROTOCOL — FULL CONTRACT DEPLOYMENT            ║");
  console.log("╚══════════════════════════════════════════════════════╝");
  console.log(`  Network:  ${network.name} (chainId: ${chainId})`);
  console.log(`  Deployer: ${deployer.address}`);
  console.log(`  Balance:  ${ethers.formatEther(balance)} ETH`);
  console.log();

  const startBlock = await ethers.provider.getBlockNumber();
  const startTime = new Date().toISOString();

  let compliance: { sk: bigint; pk: Point<bigint> };
  const existingSk = process.env.COMPLIANCE_SECRET_KEY;
  if (existingSk) {
    console.log("Step 0: Reusing existing compliance keypair...");
    const sk = BigInt(existingSk);
    const pk = mulPointEscalar(Base8, sk);
    compliance = { sk, pk };
  } else {
    console.log("Step 0: Generating fresh compliance keypair...");
    compliance = generateComplianceKeypair();
  }
  console.log(`  Compliance PK: (${compliance.pk[0]}, ${compliance.pk[1]})`);
  console.log(`  Compliance SK: *** stored in deployment artifacts ***`);
  console.log();

  console.log("Step 1: Deploying Poseidon2 library...");
  const Poseidon2Factory = await ethers.getContractFactory("Poseidon2");
  const poseidon2 = await Poseidon2Factory.deploy();
  await poseidon2.waitForDeployment();
  const poseidon2Addr = await poseidon2.getAddress();
  console.log(`  Poseidon2: ${poseidon2Addr}`);
  console.log();

  console.log("Step 2: Deploying 6 circuit verifiers...");
  const verifierPaths = [
    "contracts/verifiers/DepositVerifier.sol",
    "contracts/verifiers/WithdrawVerifier.sol",
    "contracts/verifiers/TransferVerifier.sol",
    "contracts/verifiers/JoinVerifier.sol",
    "contracts/verifiers/SplitVerifier.sol",
    "contracts/verifiers/PublicClaimVerifier.sol",
  ];

  const verifiers: { verifier: string; name: string }[] = [];
  for (const vPath of verifierPaths) {
    const v = await deployVerifier(vPath);
    verifiers.push(v);
  }
  console.log();

  console.log("Step 3: Deploying NOX-STK staking token...");
  const TokenFactory = await ethers.getContractFactory("MockERC20");
  const token = await TokenFactory.deploy("NOX Stake Token", "NOX-STK", 18);
  await token.waitForDeployment();
  const tokenAddr = await token.getAddress();
  console.log(`  NOX-STK: ${tokenAddr}`);
  console.log();

  console.log("Step 4: Deploying NoxRegistry...");
  const NoxRegistryFactory = await ethers.getContractFactory("NoxRegistry");
  const noxRegistry = await NoxRegistryFactory.deploy(
    deployer.address,
    tokenAddr,
    ethers.parseEther("1"), // minStake (>= floor)
    86400n, // unstakeDelay = 1 day (contract minimum)
    ethers.parseEther("1"), // minStakeFloor
  );
  await noxRegistry.waitForDeployment();
  const noxRegistryAddr = await noxRegistry.getAddress();
  console.log(`  NoxRegistry: ${noxRegistryAddr}`);
  console.log();

  console.log("Step 5: Deploying NoxRewardPool...");
  const RewardPoolFactory = await ethers.getContractFactory("NoxRewardPool");
  const rewardPool = await RewardPoolFactory.deploy(
    deployer.address,
    noxRegistryAddr,
  );
  await rewardPool.waitForDeployment();
  const rewardPoolAddr = await rewardPool.getAddress();
  console.log(`  NoxRewardPool: ${rewardPoolAddr}`);
  console.log();

  console.log("Step 6: Deploying DarkPool...");
  const DarkPoolFactory = await ethers.getContractFactory("DarkPool", {
    libraries: { Poseidon2: poseidon2Addr },
  });
  const darkPool = await DarkPoolFactory.deploy(
    verifiers[0].verifier, // deposit
    verifiers[1].verifier, // withdraw
    verifiers[2].verifier, // transfer
    verifiers[3].verifier, // join
    verifiers[4].verifier, // split
    verifiers[5].verifier, // publicClaim
    rewardPoolAddr,
    compliance.pk[0],
    compliance.pk[1],
    deployer.address,
  );
  await darkPool.waitForDeployment();
  const darkPoolAddr = await darkPool.getAddress();
  console.log(`  DarkPool: ${darkPoolAddr}`);
  console.log();

  console.log("Step 7: Deploying RelayerMulticall...");
  const MulticallFactory = await ethers.getContractFactory("RelayerMulticall");
  const multicall = await MulticallFactory.deploy();
  await multicall.waitForDeployment();
  const multicallAddr = await multicall.getAddress();
  console.log(`  RelayerMulticall: ${multicallAddr}`);
  console.log();

  console.log("Post-deploy: Whitelisting NOX-STK in NoxRewardPool...");
  await rewardPool.setAssetStatus(tokenAddr, true);
  console.log("  Done.");
  console.log();

  const swapRouter = process.env.SWAP_ROUTER;
  if (swapRouter && swapRouter !== ethers.ZeroAddress) {
    console.log("Post-deploy: Deploying UniswapAdaptor...");
    const AdaptorFactory = await ethers.getContractFactory("UniswapAdaptor", {
      libraries: { Poseidon2: poseidon2Addr },
    });
    const uniswapAdaptor = await AdaptorFactory.deploy(
      darkPoolAddr,
      swapRouter,
    );
    await uniswapAdaptor.waitForDeployment();
    const adaptorAddr = await uniswapAdaptor.getAddress();
    console.log(`  UniswapAdaptor: ${adaptorAddr}`);
    console.log();
  } else {
    console.log(
      "Post-deploy: SWAP_ROUTER not set; UniswapAdaptor not deployed.",
    );
    console.log();
  }

  console.log("Step 8: Verifying contracts on block explorer...");

  await tryVerify(poseidon2Addr, []);

  // Verifiers: no constructor args, TranscriptLib is inlined
  for (const v of verifiers) {
    await tryVerify(
      v.verifier,
      [],
      `${verifierPaths[verifiers.indexOf(v)]}:HonkVerifier`,
    );
  }

  await tryVerify(rewardPoolAddr, [deployer.address]);
  await tryVerify(darkPoolAddr, [
    verifiers[0].verifier,
    verifiers[1].verifier,
    verifiers[2].verifier,
    verifiers[3].verifier,
    verifiers[4].verifier,
    verifiers[5].verifier,
    rewardPoolAddr,
    compliance.pk[0].toString(),
    compliance.pk[1].toString(),
    deployer.address,
  ]);
  await tryVerify(tokenAddr, ["NOX Stake Token", "NOX-STK", 18]);
  await tryVerify(noxRegistryAddr, [deployer.address, tokenAddr, 0, 86400]);
  await tryVerify(multicallAddr, []);
  console.log();

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
    compliance: {
      publicKeyX: compliance.pk[0].toString(),
      publicKeyY: compliance.pk[1].toString(),
      // SECURITY: SK is stored separately in the secrets section
    },
    contracts: {
      poseidon2: poseidon2Addr,
      depositVerifier: verifiers[0].verifier,
      withdrawVerifier: verifiers[1].verifier,
      transferVerifier: verifiers[2].verifier,
      joinVerifier: verifiers[3].verifier,
      splitVerifier: verifiers[4].verifier,
      publicClaimVerifier: verifiers[5].verifier,
      noxRewardPool: rewardPoolAddr,
      darkPool: darkPoolAddr,
      stakingToken: tokenAddr,
      noxRegistry: noxRegistryAddr,
      relayerMulticall: multicallAddr,
    },
    libraries: {
      poseidon2: poseidon2Addr,
    },
    constructorArgs: {
      noxRewardPool: [deployer.address],
      darkPool: [
        verifiers[0].verifier,
        verifiers[1].verifier,
        verifiers[2].verifier,
        verifiers[3].verifier,
        verifiers[4].verifier,
        verifiers[5].verifier,
        rewardPoolAddr,
        compliance.pk[0].toString(),
        compliance.pk[1].toString(),
        deployer.address,
      ],
      stakingToken: ["NOX Stake Token", "NOX-STK", 18],
      noxRegistry: [deployer.address, tokenAddr, "0", "86400"],
    },
    versions: {
      solidity: "0.8.25",
      optimizer: { enabled: true, runs: 1 },
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      hardhat: require("hardhat/package.json").version,
      noir: "1.0.0-beta.19",
      bbjs: "4.0.0-nightly.20260218",
    },
    circuitHashes: {
      deposit: sha256File(path.join(circuitsDir, "deposit.json")),
      withdraw: sha256File(path.join(circuitsDir, "withdraw.json")),
      transfer: sha256File(path.join(circuitsDir, "transfer.json")),
      join: sha256File(path.join(circuitsDir, "join.json")),
      split: sha256File(path.join(circuitsDir, "split.json")),
      public_claim: sha256File(path.join(circuitsDir, "public_claim.json")),
    },
  };

  const timestamp = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
  const deployDir = path.join(__dirname, "../deployments");
  fs.mkdirSync(deployDir, { recursive: true });

  const deployFile = path.join(deployDir, `${network.name}-${timestamp}.json`);
  fs.writeFileSync(deployFile, JSON.stringify(deployment, null, 2));
  console.log(`Deployment record: ${deployFile}`);

  const latestFile = path.join(deployDir, `${network.name}-latest.json`);
  fs.writeFileSync(latestFile, JSON.stringify(deployment, null, 2));
  console.log(`Latest pointer:    ${latestFile}`);

  // Write secrets file (compliance SK) — KEEP THIS SAFE
  const secretsFile = path.join(
    deployDir,
    `${network.name}-${timestamp}.secrets.json`,
  );
  fs.writeFileSync(
    secretsFile,
    JSON.stringify(
      {
        WARNING:
          "THIS FILE CONTAINS THE COMPLIANCE PRIVATE KEY. STORE SECURELY.",
        network: network.name,
        chainId: Number(chainId),
        deployedAt: startTime,
        complianceSecretKey: compliance.sk.toString(),
        deployerAddress: deployer.address,
      },
      null,
      2,
    ),
  );
  fs.chmodSync(secretsFile, 0o600);
  console.log(`Secrets file:      ${secretsFile} (chmod 600)`);

  console.log();
  console.log("╔══════════════════════════════════════════════════════╗");
  console.log("║  DEPLOYMENT COMPLETE                                 ║");
  console.log("╚══════════════════════════════════════════════════════╝");
  console.log(`  Network:         ${network.name} (${chainId})`);
  console.log(`  Deployer:        ${deployer.address}`);
  console.log(`  DarkPool:        ${darkPoolAddr}`);
  console.log(`  NoxRegistry:     ${noxRegistryAddr}`);
  console.log(`  NoxRewardPool:   ${rewardPoolAddr}`);
  console.log(`  Staking Token:   ${tokenAddr} (NOX-STK)`);
  console.log(`  Multicall:       ${multicallAddr}`);
  console.log(`  Compliance PK:   (${compliance.pk[0]}, ${compliance.pk[1]})`);
  console.log(`  Blocks:          ${startBlock} → ${endBlock}`);
  console.log();
  console.log("Next steps:");
  console.log(
    `  1. Archive: bash scripts/archive-deployment.sh ${network.name}-${timestamp}`,
  );
  console.log(`  2. Import into nox-ctl: nox-ctl config import ${latestFile}`);
  console.log(`  3. Register nodes: nox-ctl registry register ...`);
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
