/**
 * Emit committed storage-layout snapshots for the upgradeable set, used as a tripwire:
 * `pnpm storage:check` regenerates these and `git diff --exit-code`s the directory, so ANY
 * slot/offset/type/label change forces human review before it can land.
 *
 * Each snapshot has two parts:
 *   - `storage`/`types`: solc's bare sequential layout. Empty by design for all four contracts (all state is
 *     namespaced); it trips if a bare state variable is added.
 *   - `namespaces`/`namespaceTypes`: every ERC-7201 namespace the contract reaches, member by member (slot
 *     relative to the namespace root, byte offset, type), plus the member layout of every struct those
 *     members use (e.g. KageRegistry's packed two-slot `Solver`). Read from the OpenZeppelin upgrades
 *     plugin's validation cache, which the plugin fills on every compile from a namespaced solc pass.
 *     A reorder, retype or repack inside a namespace or a nested struct changes this part.
 *
 * Limits: the namespace root is the `@custom:storage-location` annotation, not the assembly constant that
 * code reads; the constants are pinned by raw-slot tests. Before an on-chain upgrade, the deployed
 * network manifest stays the authoritative check (`validate:upgrades` covers DarkPoolV1 -> DarkPool only).
 *
 * To update the snapshot INTENTIONALLY (after an approved append-only layout change):
 *   pnpm storage:snapshot   # regenerate, then commit the .storage-layout/ diff
 *
 *   npx hardhat run scripts/snapshot-storage-layout.ts
 */

import hre, { artifacts } from "hardhat";
import { readValidations } from "@openzeppelin/hardhat-upgrades/dist/utils/validations";
import {
  getStorageLayout,
  getVersion,
  type StorageLayout,
} from "@openzeppelin/upgrades-core";
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
  { name: "KageRegistry", fqn: "contracts/kage/KageRegistry.sol:KageRegistry" },
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

// Type ids carry AST ids too (`t_struct(Solver)7430_storage`); drop them for the same reason.
function stripTypeAstIds(typeId: string): string {
  return typeId.replace(/\(([A-Za-z0-9_$.]+)\)\d+/g, "($1)");
}

type NamespaceMember = {
  contract: string;
  label: string;
  slot: string;
  offset: number;
  type: string;
};
type NamespaceType = {
  label: string;
  numberOfBytes: string;
  underlying?: string;
  members?: (string | Omit<NamespaceMember, "contract">)[];
};

function namespacedLayout(layout: StorageLayout): {
  namespaces: Record<string, NamespaceMember[]>;
  namespaceTypes: Record<string, NamespaceType>;
} {
  const namespaces: Record<string, NamespaceMember[]> = {};
  for (const id of Object.keys(layout.namespaces ?? {}).sort()) {
    namespaces[id] = (layout.namespaces?.[id] ?? []).map((item) => {
      if (item.slot === undefined || item.offset === undefined) {
        throw new Error(
          `namespace ${id} member ${item.label} has no slot/offset; the namespaced compile did not run`,
        );
      }
      return {
        contract: item.contract,
        label: item.label,
        slot: item.slot,
        offset: item.offset,
        type: stripTypeAstIds(item.type),
      };
    });
  }
  const namespaceTypes: Record<string, NamespaceType> = {};
  for (const [id, t] of Object.entries(layout.types)) {
    if (t.numberOfBytes === undefined) {
      throw new Error(`type ${id} has no size in the namespaced layout`);
    }
    const members = t.members?.map((m) => {
      if (typeof m === "string") return m;
      if (m.slot === undefined || m.offset === undefined) {
        throw new Error(
          `struct ${id} member ${m.label} has no slot/offset; the namespaced compile did not run`,
        );
      }
      return {
        label: m.label,
        slot: m.slot,
        offset: m.offset,
        type: stripTypeAstIds(m.type),
      };
    });
    namespaceTypes[stripTypeAstIds(id)] = {
      label: t.label,
      numberOfBytes: t.numberOfBytes,
      ...(t.underlying === undefined
        ? {}
        : { underlying: stripTypeAstIds(t.underlying) }),
      ...(members === undefined ? {} : { members }),
    };
  }
  const sortedTypes: Record<string, NamespaceType> = {};
  for (const id of Object.keys(namespaceTypes).sort())
    sortedTypes[id] = namespaceTypes[id];
  return { namespaces, namespaceTypes: sortedTypes };
}

type CompiledWithLayout = { storageLayout?: unknown };

async function main(): Promise<void> {
  fs.mkdirSync(OUT_DIR, { recursive: true });
  const validations = await readValidations(hre);
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
    const artifact = await artifacts.readArtifact(target.fqn);
    const ozLayout = getStorageLayout(
      validations,
      getVersion(artifact.bytecode, artifact.deployedBytecode),
    );
    const normalized = {
      ...(stripAstIds(layout) as Record<string, unknown>),
      ...namespacedLayout(ozLayout),
    };
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
