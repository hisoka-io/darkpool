/**
 * Creates the Gov Safe and the Guardian Safe from the canonical Safe v1.4.1 deployments (SafeL2 singleton,
 * SafeProxyFactory, CompatibilityFallbackHandler), or adopts them when they already exist with exactly this
 * configuration. Safe addresses are CREATE2-deterministic in (owners, threshold, SAFE_SALT_NONCE).
 *
 * Required env:
 *   SAFE_OWNERS_FILE  JSON: { "gov": { "threshold": 3, "owners": [5 addresses] },
 *                             "guardian": { "threshold": 2, "owners": [3 addresses] } }
 * Optional env:
 *   SAFE_SALT_NONCE   uint256 salt nonce (default 0)
 *   SAFES_OUT         output path (default <DEPLOYMENTS_DIR or deployments/>/<network>-safes.json)
 *
 * Usage:
 *   SAFE_OWNERS_FILE=owners.json npx hardhat run scripts/gov/create-safes.ts --network <net>
 */

import { ethers, network } from "hardhat";
import * as fs from "fs";
import * as path from "path";
import {
  SAFE_V141,
  SAFE_VERSION,
  assertCanonicalSafeStack,
  ensureSafe,
  readJsonObject,
  requireEnv,
  validateSafeConfig,
  type SafeConfig,
} from "./safe";

function safeConfig(
  owners: Record<string, unknown>,
  key: "gov" | "guardian",
): SafeConfig {
  const entry = owners[key];
  if (typeof entry !== "object" || entry === null) {
    throw new Error(`SAFE_OWNERS_FILE has no "${key}" object.`);
  }
  const { threshold, owners: list } = entry as Record<string, unknown>;
  if (!Array.isArray(list) || list.some((o) => typeof o !== "string")) {
    throw new Error(`SAFE_OWNERS_FILE ${key}.owners must be an address array.`);
  }
  if (typeof threshold !== "number") {
    throw new Error(`SAFE_OWNERS_FILE ${key}.threshold must be a number.`);
  }
  const config = {
    owners: (list as string[]).map((owner) => owner.trim()),
    threshold,
  };
  validateSafeConfig(config, key);
  return {
    owners: config.owners.map((owner) => ethers.getAddress(owner)),
    threshold,
  };
}

function saltNonce(): bigint {
  const raw = process.env.SAFE_SALT_NONCE ?? "0";
  if (!/^[0-9]+$/.test(raw.trim())) {
    throw new Error(`SAFE_SALT_NONCE=${raw} must be an unsigned decimal.`);
  }
  const value = BigInt(raw.trim());
  if (value > ethers.MaxUint256) {
    throw new Error("SAFE_SALT_NONCE exceeds uint256.");
  }
  return value;
}

async function main(): Promise<void> {
  const [submitter] = await ethers.getSigners();
  const chainId = (await ethers.provider.getNetwork()).chainId;
  const ownersFile = requireEnv("SAFE_OWNERS_FILE");
  const owners = readJsonObject(ownersFile, "SAFE_OWNERS_FILE");
  const gov = safeConfig(owners, "gov");
  const guardian = safeConfig(owners, "guardian");
  const nonce = saltNonce();
  const out =
    process.env.SAFES_OUT ??
    path.join(
      process.env.DEPLOYMENTS_DIR ?? path.join(__dirname, "../../deployments"),
      `${network.name}-safes.json`,
    );

  console.log(`Safe v${SAFE_VERSION} creation`);
  console.log(`  Network:   ${network.name} (chainId: ${chainId})`);
  console.log(`  Submitter: ${submitter.address}`);
  console.log(`  Gov:       ${gov.threshold}-of-${gov.owners.length}`);
  console.log(
    `  Guardian:  ${guardian.threshold}-of-${guardian.owners.length}`,
  );
  const shared = gov.owners.filter((owner) => guardian.owners.includes(owner));
  if (shared.length > 0) {
    console.log(
      `  WARNING: ${shared.join(", ")} own both Safes; the pauser/veto separation then rests on key custody.`,
    );
  }

  await assertCanonicalSafeStack(ethers.provider);
  for (const [name, { address }] of Object.entries(SAFE_V141)) {
    console.log(`  [ok] ${name} ${address} holds the canonical code`);
  }

  const log = (line: string) => console.log(line);
  const govSafe = await ensureSafe(submitter, gov, nonce, "Gov Safe", log);
  const guardianSafe = await ensureSafe(
    submitter,
    guardian,
    nonce,
    "Guardian Safe",
    log,
  );
  if (govSafe.address === guardianSafe.address) {
    throw new Error("Gov Safe and Guardian Safe resolved to the same address.");
  }

  const record = {
    network: network.name,
    chainId: Number(chainId),
    createdAt: new Date().toISOString(),
    safeVersion: SAFE_VERSION,
    singleton: SAFE_V141.safeL2Singleton.address,
    proxyFactory: SAFE_V141.proxyFactory.address,
    fallbackHandler: SAFE_V141.fallbackHandler.address,
    multiSendCallOnly: SAFE_V141.multiSendCallOnly.address,
    saltNonce: nonce.toString(),
    gov: {
      address: govSafe.address,
      threshold: gov.threshold,
      owners: gov.owners,
      created: govSafe.created,
      txHash: govSafe.txHash,
      gasUsed: govSafe.gasUsed.toString(),
    },
    guardian: {
      address: guardianSafe.address,
      threshold: guardian.threshold,
      owners: guardian.owners,
      created: guardianSafe.created,
      txHash: guardianSafe.txHash,
      gasUsed: guardianSafe.gasUsed.toString(),
    },
  };
  fs.mkdirSync(path.dirname(out), { recursive: true });
  fs.writeFileSync(out, JSON.stringify(record, null, 2));
  console.log();
  console.log(`GOV_SAFE=${govSafe.address}`);
  console.log(`GUARDIAN_SAFE=${guardianSafe.address}`);
  console.log(`Record: ${out}`);
}

if (require.main === module) {
  main()
    .then(() => process.exit(0))
    .catch((error) => {
      console.error(error);
      process.exit(1);
    });
}
