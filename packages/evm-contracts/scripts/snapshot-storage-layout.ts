/**
 * Emit committed storage-layout snapshots for the upgradeable set, used as a tripwire:
 * `pnpm storage:check` regenerates these and `git diff --exit-code`s the directory, so ANY
 * slot/offset/type/label change forces human review before it can land.
 *
 * Scope: these snapshots only catch bare sequential-slot (non-namespaced) layout changes; all live
 * state sits in ERC-7201 namespaces, so namespace-INTERNAL layout compatibility is enforced by
 * `validate:upgrades` (validateUpgrade -> assertStorageUpgradeSafe against DarkPoolV1), not here.
 *
 * The DarkPool/NoxRegistry/NoxRewardPool snapshots are EMPTY-BY-DESIGN (all state is namespaced); the empty
 * file is a tripwire against adding a bare sequential variable, not proof no storage was checked.
 *
 * To update the snapshot INTENTIONALLY (after an approved append-only layout change):
 *   pnpm storage:snapshot   # regenerate, then commit the .storage-layout/ diff
 *
 *   npx hardhat run scripts/snapshot-storage-layout.ts
 */

import { artifacts } from "hardhat";
import * as fs from "fs";
import * as path from "path";

const OUT_DIR = path.join(__dirname, "..", ".storage-layout");

const TARGETS: { name: string; fqn: string }[] = [
  { name: "DarkPool", fqn: "contracts/DarkPool.sol:DarkPool" },
  { name: "NoxRegistry", fqn: "contracts/nox/NoxRegistry.sol:NoxRegistry" },
  {
    name: "NoxRewardPool",
    fqn: "contracts/nox/NoxRewardPool.sol:NoxRewardPool",
  },
];

// Compiler AST node ids drift on any unrelated source edit; drop them so the snapshot only
// changes when the real layout (slot/offset/type/label/members) changes.
function stripAstIds(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(stripAstIds);
  if (value !== null && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [key, val] of Object.entries(value as Record<string, unknown>)) {
      if (key === "astId") continue;
      out[key] = stripAstIds(val);
    }
    return out;
  }
  return value;
}

type CompiledWithLayout = { storageLayout?: unknown };

async function main(): Promise<void> {
  fs.mkdirSync(OUT_DIR, { recursive: true });
  for (const target of TARGETS) {
    const buildInfo = await artifacts.getBuildInfo(target.fqn);
    if (buildInfo === undefined) {
      throw new Error(
        `no build-info for ${target.fqn}; run \`hardhat compile\` first`,
      );
    }
    const [source, contract] = target.fqn.split(":");
    const compiled = buildInfo.output.contracts?.[source]?.[contract] as
      | CompiledWithLayout
      | undefined;
    const layout = compiled?.storageLayout;
    if (layout === undefined) {
      throw new Error(
        `no storageLayout for ${target.fqn}; the hardhat-upgrades plugin must inject storageLayout output`,
      );
    }
    const normalized = stripAstIds(layout);
    const file = path.join(OUT_DIR, `${target.name}.json`);
    fs.writeFileSync(file, JSON.stringify(normalized, null, 2) + "\n");
    console.log(`  wrote .storage-layout/${target.name}.json`);
  }
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
