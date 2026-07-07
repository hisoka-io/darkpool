/**
 * DarkPoolV1 storage-surface parity guard.
 *
 *   npx tsx scripts/regen-darkpoolv1.ts        # verify (exit 1 on drift)
 *
 * DarkPoolV1.sol is the FROZEN pre-genesis upgrade baseline: the ERC-7201 namespaced storage layout as of
 * the initial deployment, which every future on-chain DarkPool upgrade must stay storage-compatible with
 * (validateUpgrade(DarkPoolV1 -> DarkPool) is the authoritative gate, run by validate-upgrade-safety.ts).
 *
 * Its only load-bearing surface is STORAGE: the inheritance list, the ERC-7201 structs (namespace + ordered
 * members), and the namespace slot constants -- these MUST match the shipped DarkPool. This guard extracts
 * that surface from BOTH contracts and fails on any divergence, so DarkPoolV1 can never be silently
 * hand-synced out of step with DarkPool. It is source-only (no compile / no artifacts), so it runs anywhere.
 *
 * Regeneration is deliberately a human edit gated by this check, not an automated rewrite: auto-mutating a
 * frozen money-contract baseline is riskier than a reviewed copy. To advance the baseline after a real
 * storage-compatible upgrade ships: copy DarkPool's storage surface into DarkPoolV1, then re-run this to zero.
 */

import * as fs from "fs";
import * as path from "path";

const CONTRACTS = path.join(__dirname, "..", "contracts");
const DARKPOOL = path.join(CONTRACTS, "DarkPool.sol");
const DARKPOOL_V1 = path.join(CONTRACTS, "DarkPoolV1.sol");

interface StorageStruct {
  namespace: string;
  name: string;
  members: string[];
}
interface StorageSurface {
  bases: string[];
  structs: Map<string, StorageStruct>;
  slots: Map<string, string>;
}

function stripComments(src: string): string {
  return src.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/[^\n]*/g, "");
}

function parseMembers(body: string): string[] {
  return stripComments(body)
    .split(";")
    .map((m) => m.replace(/\s+/g, " ").trim())
    .filter((m) => m.length > 0);
}

function extractSurface(label: string, src: string): StorageSurface {
  const baseMatch = src.match(/contract\s+\w+\s+is\s+([\s\S]*?)\{/);
  if (baseMatch === null) {
    throw new Error(`${label}: could not locate the contract inheritance list`);
  }
  const bases = baseMatch[1]
    .split(",")
    .map((b) => b.replace(/\s+/g, " ").trim())
    .filter((b) => b.length > 0);

  const structs = new Map<string, StorageStruct>();
  const structRe =
    /@custom:storage-location\s+(erc7201:[^\s*]+)[\s\S]*?struct\s+(\w+)\s*\{([\s\S]*?)\}/g;
  for (let m = structRe.exec(src); m !== null; m = structRe.exec(src)) {
    const namespace = m[1];
    const name = m[2];
    const members = parseMembers(m[3]);
    if (structs.has(namespace)) {
      throw new Error(`${label}: duplicate storage namespace ${namespace}`);
    }
    structs.set(namespace, { namespace, name, members });
  }
  if (structs.size === 0) {
    throw new Error(`${label}: no ERC-7201 storage structs found`);
  }

  const slots = new Map<string, string>();
  const slotRe =
    /bytes32\s+private\s+constant\s+(\w+_LOCATION)\s*=\s*(0x[0-9a-fA-F]+)\s*;/g;
  for (let m = slotRe.exec(src); m !== null; m = slotRe.exec(src)) {
    slots.set(m[1], m[2].toLowerCase());
  }
  if (slots.size === 0) {
    throw new Error(`${label}: no namespace slot constants found`);
  }

  return { bases, structs, slots };
}

function diffSurface(ref: StorageSurface, live: StorageSurface): string[] {
  const drift: string[] = [];

  if (ref.bases.join(", ") !== live.bases.join(", ")) {
    drift.push(
      `inheritance list differs:\n    baseline: ${ref.bases.join(", ")}\n    current : ${live.bases.join(", ")}`,
    );
  }

  const namespaces = new Set([...ref.structs.keys(), ...live.structs.keys()]);
  for (const ns of namespaces) {
    const a = ref.structs.get(ns);
    const b = live.structs.get(ns);
    if (a === undefined) {
      drift.push(`namespace ${ns} exists in DarkPool but not in the baseline`);
      continue;
    }
    if (b === undefined) {
      drift.push(`namespace ${ns} exists in the baseline but not in DarkPool`);
      continue;
    }
    if (a.members.join(" | ") !== b.members.join(" | ")) {
      drift.push(
        `namespace ${ns} members differ:\n    baseline: [${a.members.join(", ")}]\n    current : [${b.members.join(", ")}]`,
      );
    }
  }

  const slotNames = new Set([...ref.slots.keys(), ...live.slots.keys()]);
  for (const name of slotNames) {
    const a = ref.slots.get(name);
    const b = live.slots.get(name);
    if (a !== b) {
      drift.push(
        `slot constant ${name} differs: baseline=${a ?? "<absent>"} current=${b ?? "<absent>"}`,
      );
    }
  }

  return drift;
}

function main(): void {
  const baseline = extractSurface(
    "DarkPoolV1",
    fs.readFileSync(DARKPOOL_V1, "utf8"),
  );
  const current = extractSurface("DarkPool", fs.readFileSync(DARKPOOL, "utf8"));

  console.log("DarkPoolV1 storage-surface parity guard");
  console.log(
    `  namespaces: ${current.structs.size}, slot constants: ${current.slots.size}`,
  );

  const drift = diffSurface(baseline, current);
  if (drift.length > 0) {
    console.error("STORAGE-SURFACE DRIFT (DarkPoolV1 baseline vs DarkPool):");
    for (const d of drift) console.error(`  - ${d}`);
    console.error(
      "DarkPoolV1 is the frozen baseline; reconcile its storage surface with DarkPool (see file header).",
    );
    process.exit(1);
  }

  console.log("  [PASS] DarkPoolV1 storage surface matches DarkPool");
}

main();
