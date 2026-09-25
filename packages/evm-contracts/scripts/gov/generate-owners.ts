/**
 * Generates fresh Gov and Guardian Safe owner keys: a secret keys file (mode 0600, for OWNER_KEYS_FILE) and
 * a public owners file (for SAFE_OWNERS_FILE). Refuses to overwrite either file. Keys are never printed.
 *
 * Required env:
 *   OWNER_KEYS_OUT   secret output, e.g. a path inside the private secrets repo
 *   SAFE_OWNERS_OUT  public output (addresses and thresholds only)
 * Optional env:
 *   GOV_OWNERS (5), GOV_THRESHOLD (3), GUARDIAN_OWNERS (3), GUARDIAN_THRESHOLD (2)
 *
 * Usage:
 *   OWNER_KEYS_OUT=/secure/owner-keys.json SAFE_OWNERS_OUT=owners.json npx hardhat run scripts/gov/generate-owners.ts
 */

import { ethers } from "ethers";
import * as fs from "fs";
import * as path from "path";
import { requireEnv, validateSafeConfig } from "./safe";

function count(name: string, fallback: number): number {
  const raw = process.env[name];
  if (raw === undefined || raw.trim() === "") return fallback;
  if (!/^[0-9]+$/.test(raw.trim())) {
    throw new Error(`${name}=${raw} must be a positive integer.`);
  }
  return Number(raw.trim());
}

function main(): void {
  const keysOut = requireEnv("OWNER_KEYS_OUT");
  const ownersOut = requireEnv("SAFE_OWNERS_OUT");
  for (const file of [keysOut, ownersOut]) {
    if (fs.existsSync(file)) {
      throw new Error(`${file} already exists; refusing to overwrite keys.`);
    }
  }
  const groups = [
    {
      key: "gov",
      size: count("GOV_OWNERS", 5),
      threshold: count("GOV_THRESHOLD", 3),
    },
    {
      key: "guardian",
      size: count("GUARDIAN_OWNERS", 3),
      threshold: count("GUARDIAN_THRESHOLD", 2),
    },
  ] as const;

  const secrets: { label: string; address: string; privateKey: string }[] = [];
  const publicOwners: Record<string, { threshold: number; owners: string[] }> =
    {};
  for (const group of groups) {
    const wallets = Array.from({ length: group.size }, () =>
      ethers.Wallet.createRandom(),
    );
    const owners = wallets.map((wallet) => wallet.address);
    validateSafeConfig({ owners, threshold: group.threshold }, group.key);
    wallets.forEach((wallet, index) =>
      secrets.push({
        label: `${group.key}-${index + 1}`,
        address: wallet.address,
        privateKey: wallet.privateKey,
      }),
    );
    publicOwners[group.key] = { threshold: group.threshold, owners };
  }

  fs.mkdirSync(path.dirname(path.resolve(keysOut)), { recursive: true });
  fs.writeFileSync(
    keysOut,
    JSON.stringify(
      { createdAt: new Date().toISOString(), owners: secrets },
      null,
      2,
    ),
    { mode: 0o600, flag: "wx" },
  );
  fs.mkdirSync(path.dirname(path.resolve(ownersOut)), { recursive: true });
  fs.writeFileSync(ownersOut, JSON.stringify(publicOwners, null, 2), {
    flag: "wx",
  });
  console.log(`Owner keys (secret, mode 0600): ${keysOut}`);
  console.log(`Safe owners (public):           ${ownersOut}`);
  for (const [key, group] of Object.entries(publicOwners)) {
    console.log(
      `  ${key}: ${group.threshold}-of-${group.owners.length} ${group.owners.join(", ")}`,
    );
  }
}

if (require.main === module) {
  try {
    main();
    process.exit(0);
  } catch (error) {
    console.error(error);
    process.exit(1);
  }
}
