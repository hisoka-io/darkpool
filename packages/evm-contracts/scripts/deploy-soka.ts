/**
 * Deploys SOKA, the Nox staking and execution-fee token, and records it.
 *
 * Required env off hardhat/localhost:
 *   SOKA_TREASURY  receives the whole initial supply
 *   SOKA_SUPPLY    initial supply in whole SOKA (18 decimals), e.g. 1000000000
 * Optional env:
 *   SOKA_OWNER     may mint more SOKA later; defaults to SOKA_TREASURY. Renounce ownership to fix the supply.
 *   SOKA_REDEPLOY  "true" deploys a new token even when <network>-soka-latest.json points at live code
 *   SKIP_EXPLORER_VERIFY  "true" skips block-explorer verification (forks and rehearsals)
 *   DEPLOYMENTS_DIR       output directory (default deployments/)
 *
 * Writes <DEPLOYMENTS_DIR>/<network>-soka-<UTC>.json and <network>-soka-latest.json.
 *
 * Usage:
 *   SOKA_TREASURY=0x.. SOKA_SUPPLY=1000000000 npx hardhat run scripts/deploy-soka.ts --network <net>
 */

import { ethers, network, run } from "hardhat";
import * as fs from "fs";
import * as path from "path";

const SOKA_DECIMALS = 18;

export interface SokaRecord {
  readonly meta: {
    readonly network: string;
    readonly chainId: number;
    readonly deployer: string;
    readonly deployedAt: string;
    readonly block: number;
    readonly txHash: string;
  };
  readonly token: {
    readonly address: string;
    readonly name: string;
    readonly symbol: string;
    readonly decimals: number;
    readonly totalSupply: string;
    readonly treasury: string;
    readonly owner: string;
  };
  readonly constructorArgs: [string, string, string];
  readonly codeHash: string;
}

export interface SokaDeployResult {
  readonly record: SokaRecord;
  readonly latestFile: string;
  readonly reused: boolean;
}

function addressFromEnv(name: string, fallback: string | null): string {
  const raw = process.env[name];
  if (raw === undefined || raw.trim() === "") {
    if (fallback === null) {
      throw new Error(`${name} is required on network ${network.name}.`);
    }
    return fallback;
  }
  if (!ethers.isAddress(raw.trim())) {
    throw new Error(`${name}=${raw} is not a valid address.`);
  }
  const address = ethers.getAddress(raw.trim());
  if (address === ethers.ZeroAddress) {
    throw new Error(`${name} must be non-zero.`);
  }
  return address;
}

function supplyFromEnv(fallback: string | null): bigint {
  const raw = process.env.SOKA_SUPPLY ?? fallback;
  if (raw === null || raw.trim() === "") {
    throw new Error(`SOKA_SUPPLY is required on network ${network.name}.`);
  }
  let supply: bigint;
  try {
    supply = ethers.parseUnits(raw.trim(), SOKA_DECIMALS);
  } catch {
    throw new Error(
      `SOKA_SUPPLY=${raw} is not a decimal amount of whole SOKA.`,
    );
  }
  if (supply <= 0n) throw new Error("SOKA_SUPPLY must be positive.");
  return supply;
}

function readLatest(latestFile: string): SokaRecord | null {
  if (!fs.existsSync(latestFile)) return null;
  return JSON.parse(fs.readFileSync(latestFile, "utf8")) as SokaRecord;
}

export async function deploySoka(): Promise<SokaDeployResult> {
  const [deployer] = await ethers.getSigners();
  const chainId = (await ethers.provider.getNetwork()).chainId;
  const isLocal = network.name === "hardhat" || network.name === "localhost";

  const treasury = addressFromEnv(
    "SOKA_TREASURY",
    isLocal ? deployer.address : null,
  );
  const owner = addressFromEnv("SOKA_OWNER", treasury);
  const supply = supplyFromEnv(isLocal ? "1000000000" : null);

  const deployDir =
    process.env.DEPLOYMENTS_DIR ?? path.join(__dirname, "../deployments");
  fs.mkdirSync(deployDir, { recursive: true });
  const latestFile = path.join(deployDir, `${network.name}-soka-latest.json`);

  // A second run must not silently mint a second token: every consumer (NoxRegistry, fee assets, exit
  // configs) is bound to one address. Local chains restart empty, so a stale record never applies there.
  const previous = isLocal ? null : readLatest(latestFile);
  if (
    previous !== null &&
    process.env.SOKA_REDEPLOY !== "true" &&
    previous.meta.chainId === Number(chainId) &&
    ethers.keccak256(await ethers.provider.getCode(previous.token.address)) ===
      previous.codeHash
  ) {
    console.log(
      `SOKA already deployed at ${previous.token.address} (${latestFile}); set SOKA_REDEPLOY=true for a new one.`,
    );
    return { record: previous, latestFile, reused: true };
  }

  console.log("SOKA deployment");
  console.log(`  Network:  ${network.name} (chainId: ${chainId})`);
  console.log(`  Deployer: ${deployer.address}`);
  console.log(`  Treasury: ${treasury}`);
  console.log(`  Owner:    ${owner}`);
  console.log(`  Supply:   ${ethers.formatUnits(supply, SOKA_DECIMALS)} SOKA`);

  const startTime = new Date().toISOString();
  const factory = await ethers.getContractFactory("SokaToken");
  const token = await factory.deploy(treasury, supply, owner);
  await token.waitForDeployment();
  const receipt = await token.deploymentTransaction()?.wait();
  if (receipt === null || receipt === undefined || receipt.status !== 1) {
    throw new Error("SokaToken deployment transaction did not succeed.");
  }
  const address = await token.getAddress();

  const checks: { label: string; ok: boolean }[] = [
    { label: "name is Soka", ok: (await token.name()) === "Soka" },
    { label: "symbol is SOKA", ok: (await token.symbol()) === "SOKA" },
    {
      label: "decimals is 18",
      ok: Number(await token.decimals()) === SOKA_DECIMALS,
    },
    {
      label: "treasury holds the whole supply",
      ok:
        (await token.totalSupply()) === supply &&
        (await token.balanceOf(treasury)) === supply,
    },
    { label: "owner is SOKA_OWNER", ok: (await token.owner()) === owner },
  ];
  for (const check of checks) {
    console.log(`  [${check.ok ? "ok" : "FAIL"}] ${check.label}`);
    if (!check.ok) throw new Error(`SokaToken check failed: ${check.label}`);
  }

  const record: SokaRecord = {
    meta: {
      network: network.name,
      chainId: Number(chainId),
      deployer: deployer.address,
      deployedAt: startTime,
      block: receipt.blockNumber,
      txHash: receipt.hash,
    },
    token: {
      address,
      name: "Soka",
      symbol: "SOKA",
      decimals: SOKA_DECIMALS,
      totalSupply: supply.toString(),
      treasury,
      owner,
    },
    constructorArgs: [treasury, supply.toString(), owner],
    codeHash: ethers.keccak256(await ethers.provider.getCode(address)),
  };
  const timestamp = startTime.replace(/[:.]/g, "-").slice(0, 19);
  const recordFile = path.join(
    deployDir,
    `${network.name}-soka-${timestamp}.json`,
  );
  fs.writeFileSync(recordFile, JSON.stringify(record, null, 2));
  fs.writeFileSync(latestFile, JSON.stringify(record, null, 2));
  console.log(`  SokaToken: ${address}`);
  console.log(`  Record:    ${recordFile}`);

  if (!isLocal && process.env.SKIP_EXPLORER_VERIFY !== "true") {
    try {
      await run("verify:verify", {
        address,
        constructorArguments: record.constructorArgs,
        contract: "contracts/nox/SokaToken.sol:SokaToken",
      });
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      console.log(`  Verify ${address}: ${msg}`);
    }
  }

  return { record, latestFile, reused: false };
}

if (require.main === module) {
  deploySoka()
    .then(() => process.exit(0))
    .catch((error) => {
      console.error(error);
      process.exit(1);
    });
}
