/**
 * Blocking upgrade-safety gate. Run in CI on every PR that touches the upgradeable set:
 *
 *   npx hardhat run scripts/validate-upgrade-safety.ts
 *
 * It fails (exit 1) if any of the three UUPS implementations is upgrade-unsafe, if the live
 * DarkPool storage is incompatible with the pinned DarkPoolV1 baseline (namespace-internal
 * reorder/retype included), if an unapproved unsafe flag or source annotation is used, or if the
 * DarkPool external-library link set drifts from the pinned Poseidon2-only record.
 *
 * The ONLY unsafe option permitted anywhere is `external-library-linking`, and only for
 * DarkPool (it links the stateless, bytecode-verified Poseidon2 pure library). Every
 * storage-relaxing / check-skipping flag is banned; the guard below enforces that in code.
 */

import { ethers, upgrades, artifacts } from "hardhat";
import type { ContractFactory } from "ethers";
import * as fs from "fs";
import * as path from "path";

const POSEIDON2_SOURCE = "contracts/Poseidon/Poseidon2.sol";
const POSEIDON2_LIB = "Poseidon2";
// Link address is irrelevant to storage-layout validation; a fixed placeholder keeps the
// script side-effect free (no deploy). The real address is set at deploy time.
const POSEIDON2_LINK_PLACEHOLDER = "0x0000000000000000000000000000000000000001";

const PIN_FILE = path.join(
  __dirname,
  "..",
  ".storage-layout",
  "linked-libraries.json",
);

// Options that relax storage-layout / proxy-safety checks. None may ever appear.
const BANNED_OPTION_KEYS = [
  "unsafeSkipStorageCheck",
  "unsafeSkipAllChecks",
  "unsafeSkipProxyAdminCheck",
  "unsafeAllowRenames",
  "unsafeAllowCustomTypes",
  "unsafeAllowLinkedLibraries",
];
const ALLOWED_UNSAFE_ALLOW = "external-library-linking";

// The only source-level unsafe annotation permitted on a deployed contract: silencing the constructor
// check on a UUPS impl (the constructor only runs _disableInitializers). Any storage- or
// initializer-relaxing annotation is banned.
const ALLOWED_SOURCE_ANNOTATION = "constructor";
const ANNOTATION_TAG = "@custom:oz-upgrades-unsafe-allow";
const REAL_CONTRACT_SOURCES = [
  "contracts/DarkPool.sol",
  "contracts/nox/NoxRegistry.sol",
  "contracts/nox/NoxRewardPool.sol",
];

type ValidateOpts = NonNullable<
  Parameters<typeof upgrades.validateImplementation>[1]
>;

function assertSafeOpts(label: string, opts: ValidateOpts): void {
  const record = opts as unknown as Record<string, unknown>;
  for (const key of Object.keys(record)) {
    if (BANNED_OPTION_KEYS.includes(key)) {
      throw new Error(
        `banned unsafe option "${key}" on ${label}; storage-relaxing flags are prohibited`,
      );
    }
  }
  for (const flag of opts.unsafeAllow ?? []) {
    if (flag !== ALLOWED_UNSAFE_ALLOW) {
      throw new Error(
        `banned unsafeAllow "${flag}" on ${label}; only "${ALLOWED_UNSAFE_ALLOW}" is permitted`,
      );
    }
  }
}

async function validateOne(
  label: string,
  factory: ContractFactory,
  opts: ValidateOpts,
): Promise<boolean> {
  assertSafeOpts(label, opts);
  try {
    await upgrades.validateImplementation(factory, opts);
    console.log(`  [PASS] ${label}`);
    return true;
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    console.error(`  [FAIL] ${label}: ${msg}`);
    return false;
  }
}

/** Run assertStorageUpgradeSafe(reference -> next). Fails on any storage-incompatible change. */
async function validatePair(
  label: string,
  reference: ContractFactory,
  next: ContractFactory,
  opts: ValidateOpts,
): Promise<boolean> {
  assertSafeOpts(label, opts);
  try {
    await upgrades.validateUpgrade(reference, next, opts);
    console.log(`  [PASS] ${label}`);
    return true;
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    console.error(`  [FAIL] ${label}: ${msg}`);
    return false;
  }
}

/** Assert the deployed contracts carry only the approved `oz-upgrades-unsafe-allow constructor`
 *  annotation; any storage/initializer-relaxing annotation fails the gate. Mocks are out of scope. */
function assertAnnotationScan(): void {
  for (const rel of REAL_CONTRACT_SOURCES) {
    const abs = path.join(__dirname, "..", rel);
    const src = fs.readFileSync(abs, "utf8");
    const lines = src.split("\n");
    for (let i = 0; i < lines.length; i++) {
      const idx = lines[i].indexOf(ANNOTATION_TAG);
      if (idx === -1) continue;
      const payload = lines[i].slice(idx + ANNOTATION_TAG.length).trim();
      if (payload !== ALLOWED_SOURCE_ANNOTATION) {
        throw new Error(
          `${rel}:${i + 1} carries "${ANNOTATION_TAG} ${payload}"; only ` +
            `"${ANNOTATION_TAG} ${ALLOWED_SOURCE_ANNOTATION}" is permitted`,
        );
      }
    }
    console.log(`  [PASS] ${rel} annotation scan (constructor only)`);
  }
}

/** Assert DarkPool links exactly Poseidon2 (and nothing else), the Nox contracts link
 *  nothing, and the link set matches the committed pin. Fails on any drift. */
async function assertLibraryLinkPin(): Promise<void> {
  const darkpool = await artifacts.readArtifact("DarkPool");
  const pairs: { source: string; lib: string }[] = [];
  for (const source of Object.keys(darkpool.linkReferences)) {
    for (const lib of Object.keys(darkpool.linkReferences[source])) {
      pairs.push({ source, lib });
    }
  }
  if (pairs.length !== 1) {
    throw new Error(
      `DarkPool must link exactly one external library, found ${pairs.length}: ${JSON.stringify(pairs)}`,
    );
  }
  if (pairs[0].lib !== POSEIDON2_LIB || pairs[0].source !== POSEIDON2_SOURCE) {
    throw new Error(
      `DarkPool links an unexpected library ${pairs[0].source}:${pairs[0].lib}; only ${POSEIDON2_SOURCE}:${POSEIDON2_LIB} is pinned`,
    );
  }

  for (const name of ["NoxRegistry", "NoxRewardPool"]) {
    const art = await artifacts.readArtifact(name);
    const count = Object.keys(art.linkReferences).length;
    if (count !== 0) {
      throw new Error(
        `${name} must not link any external library, found ${count}`,
      );
    }
  }

  const current = { DarkPool: { [POSEIDON2_LIB]: POSEIDON2_SOURCE } };
  const serialized = JSON.stringify(current, null, 2);
  if (fs.existsSync(PIN_FILE)) {
    const pinned = fs.readFileSync(PIN_FILE, "utf8").trim();
    if (pinned !== serialized) {
      throw new Error(
        `linked-libraries.json drift.\n  pinned : ${pinned}\n  current: ${serialized}\n` +
          `A change to the DarkPool link set must be reviewed; update the pin intentionally if correct.`,
      );
    }
    console.log("  [PASS] DarkPool link pin matches (Poseidon2 only)");
  } else {
    fs.mkdirSync(path.dirname(PIN_FILE), { recursive: true });
    fs.writeFileSync(PIN_FILE, serialized + "\n");
    console.log("  [INIT] wrote .storage-layout/linked-libraries.json");
  }
}

async function main(): Promise<void> {
  console.log("Upgrade-safety gate");
  console.log("Step 1: DarkPool library-link pin...");
  await assertLibraryLinkPin();

  console.log("Step 2: source annotation scan...");
  assertAnnotationScan();

  console.log("Step 3: validateImplementation (UUPS)...");
  const linkedLibs = {
    [`${POSEIDON2_SOURCE}:${POSEIDON2_LIB}`]: POSEIDON2_LINK_PLACEHOLDER,
  };
  const darkPoolFactory = await ethers.getContractFactory("DarkPool", {
    libraries: linkedLibs,
  });
  const darkPoolV1Factory = await ethers.getContractFactory("DarkPoolV1", {
    libraries: linkedLibs,
  });
  const noxRegistryFactory = await ethers.getContractFactory("NoxRegistry");
  const noxRewardPoolFactory = await ethers.getContractFactory("NoxRewardPool");

  const darkPoolOpts: ValidateOpts = {
    kind: "uups",
    unsafeAllow: [ALLOWED_UNSAFE_ALLOW],
  };

  const results = [
    await validateOne("DarkPool", darkPoolFactory, darkPoolOpts),
    await validateOne("NoxRegistry", noxRegistryFactory, { kind: "uups" }),
    await validateOne("NoxRewardPool", noxRewardPoolFactory, { kind: "uups" }),
  ];

  // Storage-compat gate: assertStorageUpgradeSafe(DarkPoolV1 -> DarkPool). With V1 == current this
  // passes; it exists to catch a FUTURE storage-incompatible DarkPool change (a namespace-internal
  // reorder/retype the bare-sequential snapshot cannot see). Two blind spots by construction:
  //   1. A MerkleTreeLib.Tree struct reshape is invisible here: DarkPoolV1 and DarkPool import the
  //      SAME library, so both TreeStorage structs move in lockstep and the diff cancels. Guard it
  //      with the raw-slot test on the live Tree members (test/upgrade/Continuity.test.ts), not this pair.
  //   2. This checks the in-repo V1 baseline, not real proxy storage. Before any on-chain upgrade,
  //      re-run validateUpgrade against the DEPLOYED .openzeppelin/<network>.json manifest on the fork
  //      job -- that anchors to the live layout and is the authoritative pre-upgrade check.
  console.log(
    "Step 4: validateUpgrade (DarkPoolV1 -> DarkPool storage compat)...",
  );
  results.push(
    await validatePair(
      "DarkPoolV1 -> DarkPool",
      darkPoolV1Factory,
      darkPoolFactory,
      darkPoolOpts,
    ),
  );

  if (results.some((ok) => !ok)) {
    console.error("UPGRADE-SAFETY VALIDATION FAILED");
    process.exit(1);
  }
  console.log("ALL CHECKS PASS");
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
