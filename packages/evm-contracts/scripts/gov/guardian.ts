/**
 * Guardian Safe actions on NoxRegistry: freeze or unfreeze nodes (SLASHER_ROLE, held directly by the
 * Guardian Safe, so no Timelock). A frozen node drops out of the topology and rewards but stays registered and
 * slashable. Several nodes go out in one atomic Safe transaction; nodes already in the target state are
 * skipped, so a re-run is a no-op.
 *
 * Required env:
 *   GUARDIAN_ACTION  freeze | unfreeze
 *   NODE_ADDRESSES   comma-separated node addresses
 *   OWNER_KEYS_FILE  Guardian Safe owner keys (see scripts/gov/safe.ts)
 * Optional env:
 *   DEPLOYMENT_FILE  deploy record (default <DEPLOYMENTS_DIR or deployments/>/<network>-latest.json)
 *   GUARDIAN_SAFE, NOX_REGISTRY  override the record
 *   DRY_RUN          "true" signs and simulates with eth_call; nothing is sent
 *
 * Usage:
 *   GUARDIAN_ACTION=freeze NODE_ADDRESSES=0x..,0x.. OWNER_KEYS_FILE=keys.json \
 *     npx hardhat run scripts/gov/guardian.ts --network <net>
 */

import { ethers, network } from "hardhat";
import * as fs from "fs";
import * as path from "path";
import {
  Operation,
  envAddress,
  envFlag,
  execSafeTransaction,
  loadOwnerKeys,
  multiSendCallOnly,
  readJsonObject,
  requireEnv,
  type SafeCall,
} from "./safe";

type GuardianAction = "freeze" | "unfreeze";

function parseAction(raw: string): GuardianAction {
  if (raw === "freeze" || raw === "unfreeze") return raw;
  throw new Error(`GUARDIAN_ACTION must be freeze or unfreeze, got ${raw}.`);
}

function parseNodeAddress(raw: string): string {
  if (!ethers.isAddress(raw)) {
    throw new Error(`NODE_ADDRESSES entry ${raw} is not a valid address.`);
  }
  return ethers.getAddress(raw);
}

async function main(): Promise<void> {
  const [submitter] = await ethers.getSigners();
  const action = parseAction(requireEnv("GUARDIAN_ACTION"));
  const targets = requireEnv("NODE_ADDRESSES")
    .split(",")
    .map((raw) => raw.trim())
    .filter((raw) => raw !== "")
    .map(parseNodeAddress);
  if (new Set(targets).size !== targets.length) {
    throw new Error("NODE_ADDRESSES lists a node twice.");
  }
  const deploymentFile =
    process.env.DEPLOYMENT_FILE ??
    path.join(
      process.env.DEPLOYMENTS_DIR ?? path.join(__dirname, "../../deployments"),
      `${network.name}-latest.json`,
    );
  const record = fs.existsSync(deploymentFile)
    ? readJsonObject(deploymentFile, "DEPLOYMENT_FILE")
    : {};
  const governance = (record.governance ?? {}) as Record<string, unknown>;
  const contracts = (record.contracts ?? {}) as Record<string, unknown>;
  const guardianSafe = envAddress("GUARDIAN_SAFE", governance.guardianSafe);
  const registryAddress = envAddress("NOX_REGISTRY", contracts.noxRegistry);
  const dryRun = envFlag("DRY_RUN", false);
  const registry = await ethers.getContractAt("NoxRegistry", registryAddress);

  const slasher = await registry.SLASHER_ROLE();
  if (!(await registry.hasRole(slasher, guardianSafe))) {
    throw new Error(
      `Guardian Safe ${guardianSafe} does not hold SLASHER_ROLE on NoxRegistry ${registryAddress}.`,
    );
  }

  console.log(`Guardian ${action} on NoxRegistry ${registryAddress}`);
  console.log(`  Guardian Safe: ${guardianSafe}`);
  const wantFrozen = action === "freeze";
  const calls: SafeCall[] = [];
  for (const address of targets) {
    const row = await registry.relayers(address);
    if (!row.isRegistered) {
      throw new Error(`${address} is not registered on ${registryAddress}.`);
    }
    if (row.frozen === wantFrozen) {
      console.log(
        `  skip ${address}: already ${action === "freeze" ? "frozen" : "unfrozen"}`,
      );
      continue;
    }
    calls.push({
      to: registryAddress,
      value: 0n,
      data:
        action === "freeze"
          ? registry.interface.encodeFunctionData("freeze", [address])
          : registry.interface.encodeFunctionData("unfreeze", [address]),
    });
    console.log(`  ${action} ${address}`);
  }
  if (calls.length === 0) {
    console.log("  Nothing to do.");
    return;
  }

  const [call, operation] =
    calls.length === 1
      ? [calls[0], Operation.Call]
      : [multiSendCallOnly(calls), Operation.DelegateCall];
  await execSafeTransaction({
    safe: guardianSafe,
    call,
    operation,
    keys: loadOwnerKeys(requireEnv("OWNER_KEYS_FILE")),
    submitter,
    dryRun,
    label: `guardian ${action}`,
    log: (line) => console.log(line),
  });
  if (dryRun) return;

  for (const address of targets) {
    const row = await registry.relayers(address);
    const active = await registry.isActiveRelayer(address);
    if (row.frozen !== wantFrozen || active === wantFrozen) {
      throw new Error(
        `${address}: frozen=${row.frozen} active=${active} after ${action}.`,
      );
    }
    console.log(`  [ok] ${address} frozen=${row.frozen} active=${active}`);
  }
}

if (require.main === module) {
  main()
    .then(() => process.exit(0))
    .catch((error) => {
      console.error(error);
      process.exit(1);
    });
}
