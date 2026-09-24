/**
 * Executes arbitrary calls from a Safe, signed by owner keys from a local keys file, optionally through the
 * OZ TimelockController the Safe proposes to.
 *
 * Required env:
 *   SAFE             the executing Safe
 *   OWNER_KEYS_FILE  { "owners": [{ "address": "0x..", "privateKey": "0x.." }] }, mode 0600; keys never logged
 *   CALLS_FILE       JSON array; each entry is { "to", "data", "value"? } or
 *                    { "to", "signature": "freeze(address)", "args": [..], "value"? }
 * Optional env:
 *   VIA_TIMELOCK     Timelock address: run the calls as one Timelock batch (schedule+execute in one Safe tx
 *                    when the min delay is 0, schedule then execute otherwise)
 *   TIMELOCK_SALT    bytes32 batch salt (default keccak256 of the encoded calls, so a re-run resumes)
 *   WAIT_FOR_DELAY   "false" leaves a delayed batch scheduled instead of polling until it is ready (default true)
 *   DRY_RUN          "true" signs and simulates with eth_call; nothing is sent
 *
 * A direct (no Timelock) multi-call runs atomically through MultiSendCallOnly.
 *
 * Usage:
 *   SAFE=0x.. OWNER_KEYS_FILE=keys.json CALLS_FILE=calls.json npx hardhat run scripts/gov/safe-exec.ts --network <net>
 */

import { ethers } from "hardhat";
import * as fs from "fs";
import {
  Operation,
  envAddress,
  envFlag,
  execSafeTransaction,
  executeThroughTimelock,
  loadOwnerKeys,
  multiSendCallOnly,
  requireEnv,
  type SafeCall,
} from "./safe";

function parseCalls(file: string): SafeCall[] {
  if (!fs.existsSync(file))
    throw new Error(`CALLS_FILE ${file} does not exist.`);
  let parsed: unknown;
  try {
    parsed = JSON.parse(fs.readFileSync(file, "utf8"));
  } catch (e) {
    const detail = e instanceof Error ? e.message : String(e);
    throw new Error(`CALLS_FILE ${file} is not valid JSON: ${detail}`);
  }
  if (!Array.isArray(parsed) || parsed.length === 0) {
    throw new Error(`CALLS_FILE ${file} must be a non-empty JSON array.`);
  }
  return parsed.map((entry: unknown, index) => {
    const where = `CALLS_FILE[${index}]`;
    if (typeof entry !== "object" || entry === null) {
      throw new Error(`${where} must be an object.`);
    }
    const { to, value, data, signature, args } = entry as Record<
      string,
      unknown
    >;
    if (typeof to !== "string" || !ethers.isAddress(to)) {
      throw new Error(`${where}.to is not a valid address.`);
    }
    let callData: string;
    if (typeof data === "string") {
      if (!ethers.isHexString(data)) {
        throw new Error(`${where}.data is not hex.`);
      }
      callData = data;
    } else if (typeof signature === "string") {
      const fragment = ethers.FunctionFragment.from(signature);
      callData = new ethers.Interface([fragment]).encodeFunctionData(
        fragment,
        Array.isArray(args) ? args : [],
      );
    } else {
      throw new Error(`${where} needs "data" or "signature" + "args".`);
    }
    let callValue = 0n;
    if (value !== undefined) {
      if (typeof value !== "string" && typeof value !== "number") {
        throw new Error(`${where}.value must be a decimal string of wei.`);
      }
      callValue = BigInt(value);
    }
    return { to: ethers.getAddress(to), value: callValue, data: callData };
  });
}

async function main(): Promise<void> {
  const [submitter] = await ethers.getSigners();
  const safe = envAddress("SAFE", null);
  const keys = loadOwnerKeys(requireEnv("OWNER_KEYS_FILE"));
  const calls = parseCalls(requireEnv("CALLS_FILE"));
  const dryRun = envFlag("DRY_RUN", false);
  const log = (line: string) => console.log(line);
  const timelockRaw = process.env.VIA_TIMELOCK;

  console.log(`Safe execution from ${safe} (${calls.length} call(s))`);
  console.log(`  Submitter: ${submitter.address}`);
  for (const call of calls) {
    console.log(
      `  -> ${call.to} value ${call.value} data ${call.data.slice(0, 10)}..`,
    );
  }

  if (timelockRaw !== undefined && timelockRaw.trim() !== "") {
    const timelock = envAddress("VIA_TIMELOCK", null);
    const saltRaw = process.env.TIMELOCK_SALT;
    const salt =
      saltRaw !== undefined && saltRaw.trim() !== ""
        ? ethers.zeroPadValue(saltRaw.trim(), 32)
        : ethers.keccak256(
            ethers.AbiCoder.defaultAbiCoder().encode(
              ["tuple(address,uint256,bytes)[]"],
              [calls.map((call) => [call.to, call.value, call.data])],
            ),
          );
    const result = await executeThroughTimelock({
      safe,
      timelock,
      batch: { calls, predecessor: ethers.ZeroHash, salt },
      keys,
      submitter,
      dryRun,
      waitForDelay: envFlag("WAIT_FOR_DELAY", true),
      label: "timelock batch",
      log,
    });
    console.log(`Outcome: ${result.outcome} (operation ${result.operationId})`);
    return;
  }

  const [call, operation] =
    calls.length === 1
      ? [calls[0], Operation.Call]
      : [multiSendCallOnly(calls), Operation.DelegateCall];
  await execSafeTransaction({
    safe,
    call,
    operation,
    keys,
    submitter,
    dryRun,
    label: "safe tx",
    log,
  });
}

if (require.main === module) {
  main()
    .then(() => process.exit(0))
    .catch((error) => {
      console.error(error);
      process.exit(1);
    });
}
