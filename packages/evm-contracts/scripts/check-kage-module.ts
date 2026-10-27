/**
 * Checks the Kage settlement module DarkPool holds against the layout deploy.ts registered it with, after the
 * Timelock has executed the registration call the deployment record carries. Exits non-zero on any mismatch.
 *
 * Env:
 *   DEPLOYMENT_RECORD  record written by deploy.ts with KAGE_MODULE=on (default deployments/<network>-latest.json)
 *
 * Usage:
 *   npx hardhat run scripts/check-kage-module.ts --network <net>
 */

import { ethers, network } from "hardhat";
import * as fs from "fs";
import * as path from "path";
import { kageModuleProblems } from "./deploy";

interface KageRecordView {
  readonly contracts: { readonly darkPool: string };
  readonly kage: {
    readonly settlement: string;
    readonly verifier: string;
  } | null;
}

export async function checkKageModule(recordFile: string): Promise<void> {
  const record = JSON.parse(
    fs.readFileSync(recordFile, "utf8"),
  ) as KageRecordView;
  if (record.kage === null || record.kage === undefined) {
    throw new Error(
      `${recordFile} records no Kage module (deployed with KAGE_MODULE=off).`,
    );
  }
  const darkPool = await ethers.getContractAt(
    "DarkPool",
    record.contracts.darkPool,
  );
  const problems = await kageModuleProblems(
    darkPool,
    record.kage.settlement,
    record.kage.verifier,
  );
  if (problems.length > 0) {
    throw new Error(
      `Kage module ${record.kage.settlement} on DarkPool ${record.contracts.darkPool}: ${problems.join("; ")}`,
    );
  }
  console.log(
    `Kage module ${record.kage.settlement} matches the registered layout (maxPast 0).`,
  );
}

if (require.main === module) {
  const recordFile =
    process.env.DEPLOYMENT_RECORD ??
    path.join(__dirname, "../deployments", `${network.name}-latest.json`);
  checkKageModule(recordFile)
    .then(() => process.exit(0))
    .catch((error) => {
      console.error(error);
      process.exit(1);
    });
}
