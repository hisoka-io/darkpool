/**
 * Checks the Kage settlement module against the layout deploy.ts registers it with. A controller can never
 * re-register, so the check runs twice:
 *   - before execution, with KAGE_OPERATION_ID set: decodes the call the Timelock holds under that operation id and
 *     refuses unless it is exactly the registration of the recorded KageSettlement with the Kage verifier and the
 *     Kage layout (2 nullifiers, 4 outputs, 0 module words, maxPast 0, maxFuture unbounded);
 *   - after execution, without it: reads the module DarkPool holds.
 * Exits non-zero on any mismatch.
 *
 * Env:
 *   DEPLOYMENT_RECORD  record written by deploy.ts with KAGE_MODULE=on (default deployments/<network>-latest.json)
 *   KAGE_OPERATION_ID  the Timelock operation id (bytes32) of the scheduled registration
 *
 * Usage:
 *   KAGE_OPERATION_ID=0x.. npx hardhat run scripts/check-kage-module.ts --network <net>
 *   npx hardhat run scripts/check-kage-module.ts --network <net>
 */

import { ethers, network } from "hardhat";
import * as fs from "fs";
import * as path from "path";
import {
  KAGE_MODULE_LAYOUT,
  kageModuleProblems,
  kageModuleRegistration,
} from "./deploy";

interface KageRecordView {
  readonly meta: { readonly startBlock: number };
  readonly governance: { readonly timelock: string };
  readonly contracts: { readonly darkPool: string };
  readonly kage: {
    readonly settlement: string;
    readonly verifier: string;
  } | null;
}

/** One call of a scheduled Timelock operation, as its CallScheduled event carries it. */
export interface ScheduledCall {
  readonly target: string;
  readonly value: bigint;
  readonly data: string;
}

const REGISTER_MODULE = new ethers.Interface([
  "function registerSettlementModule(address controller, address moduleVerifier, uint8 nullifierCount, uint8 outputCount, uint8 extraCount, uint32 maxPast, uint32 maxFuture)",
]);
const OPERATION_ID_RE = /^0x[0-9a-fA-F]{64}$/;

function readKageRecord(recordFile: string): KageRecordView & {
  readonly kage: NonNullable<KageRecordView["kage"]>;
} {
  const record = JSON.parse(
    fs.readFileSync(recordFile, "utf8"),
  ) as KageRecordView;
  if (record.kage === null || record.kage === undefined) {
    throw new Error(
      `${recordFile} records no Kage module (deployed with KAGE_MODULE=off).`,
    );
  }
  return { ...record, kage: record.kage };
}

/**
 * Compares the calls of a scheduled operation with the one Kage registration call. The operation must hold that
 * call alone, so nothing else rides on the same approval, and its calldata must be the canonical encoding.
 */
export function scheduledKageRegistrationProblems(
  calls: readonly ScheduledCall[],
  darkPool: string,
  settlement: string,
  kageVerifier: string,
): string[] {
  if (calls.length !== 1) {
    return [
      `operation holds ${calls.length} calls; the Kage registration must be scheduled as a single call`,
    ];
  }
  const [call] = calls;
  const problems: string[] = [];
  if (ethers.getAddress(call.target) !== ethers.getAddress(darkPool)) {
    problems.push(`target is ${call.target}, expected DarkPool ${darkPool}`);
  }
  if (call.value !== 0n) problems.push(`value is ${call.value}, expected 0`);
  const fragment = REGISTER_MODULE.getFunction("registerSettlementModule");
  const selector = ethers.dataSlice(call.data, 0, 4);
  if (fragment === null || selector !== fragment.selector) {
    problems.push(
      `calldata selector ${selector} is not registerSettlementModule`,
    );
    return problems;
  }
  const args = REGISTER_MODULE.decodeFunctionData(fragment, call.data);
  if (ethers.getAddress(args[0]) !== ethers.getAddress(settlement)) {
    problems.push(`controller is ${args[0]}, expected ${settlement}`);
  }
  if (ethers.getAddress(args[1]) !== ethers.getAddress(kageVerifier)) {
    problems.push(`module verifier is ${args[1]}, expected ${kageVerifier}`);
  }
  const fields = [
    "nullifierCount",
    "outputCount",
    "extraCount",
    "maxPast",
    "maxFuture",
  ] as const;
  fields.forEach((field, i) => {
    const actual = BigInt(args[2 + i]);
    if (actual !== KAGE_MODULE_LAYOUT[field]) {
      problems.push(
        `${field} is ${actual}, expected ${KAGE_MODULE_LAYOUT[field]}`,
      );
    }
  });
  const canonical = kageModuleRegistration(darkPool, settlement, kageVerifier);
  if (
    problems.length === 0 &&
    call.data.toLowerCase() !== canonical.data.toLowerCase()
  ) {
    problems.push(
      "calldata decodes to the Kage registration but is not its canonical encoding",
    );
  }
  return problems;
}

export async function checkScheduledKageRegistration(
  recordFile: string,
  operationId: string,
): Promise<void> {
  if (!OPERATION_ID_RE.test(operationId)) {
    throw new Error(
      `KAGE_OPERATION_ID=${operationId} must be a 0x-prefixed 32-byte Timelock operation id.`,
    );
  }
  const record = readKageRecord(recordFile);
  const timelock = await ethers.getContractAt(
    "TimelockController",
    record.governance.timelock,
  );
  if (await timelock.isOperationDone(operationId)) {
    throw new Error(
      `Timelock operation ${operationId} has already executed; run without KAGE_OPERATION_ID to check the ` +
        "registered module.",
    );
  }
  if (!(await timelock.isOperationPending(operationId))) {
    throw new Error(
      `Timelock ${record.governance.timelock} holds no pending operation ${operationId} (never scheduled or ` +
        "cancelled).",
    );
  }
  const events = await timelock.queryFilter(
    timelock.filters.CallScheduled(operationId),
    record.meta.startBlock,
  );
  const calls: ScheduledCall[] = events.map((event) => ({
    target: String(event.args.target),
    value: BigInt(event.args.value),
    data: String(event.args.data),
  }));
  const problems = scheduledKageRegistrationProblems(
    calls,
    record.contracts.darkPool,
    record.kage.settlement,
    record.kage.verifier,
  );
  if (problems.length > 0) {
    throw new Error(
      `Timelock operation ${operationId} does not register Kage module ${record.kage.settlement} as recorded: ` +
        problems.join("; "),
    );
  }
  console.log(
    `Timelock operation ${operationId} registers Kage module ${record.kage.settlement} with the Kage verifier ` +
      "and layout (maxPast 0).",
  );
}

export async function checkKageModule(recordFile: string): Promise<void> {
  const record = readKageRecord(recordFile);
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
  const operationId = (process.env.KAGE_OPERATION_ID ?? "").trim();
  (operationId === ""
    ? checkKageModule(recordFile)
    : checkScheduledKageRegistration(recordFile, operationId)
  )
    .then(() => process.exit(0))
    .catch((error) => {
      console.error(error);
      process.exit(1);
    });
}
