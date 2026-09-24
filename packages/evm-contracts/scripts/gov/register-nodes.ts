/**
 * Registers a node set on NoxRegistry as privileged (zero-stake) relayers: Gov Safe -> Timelock ->
 * registerPrivileged, as ONE Timelock batch. Idempotent: nodes already registered with the same profile are
 * skipped, and re-running after success does nothing. Then verifies every node's on-chain row.
 *
 * Required env:
 *   NODES_FILE       { "chainId"?: 421614, "nodes": [{ "name"?, "address", "sphinxKey", "url",
 *                      "ingressUrl"?, "metadataUrl"?, "role": 1|2|3 }] }
 *   OWNER_KEYS_FILE  Gov Safe owner keys (see scripts/gov/safe.ts); not needed when nothing is left to register
 * Optional env:
 *   DEPLOYMENT_FILE  deploy record (default <DEPLOYMENTS_DIR or deployments/>/<network>-latest.json) supplying the addresses below
 *   GOV_SAFE, TIMELOCK, NOX_REGISTRY  override the record
 *   REREGISTER_MISMATCHED  "true" replaces a registered node whose profile differs (forceUnregister +
 *                          registerPrivileged in the same batch); otherwise a mismatch fails verification
 *   EXPECT_EXACT_SET "true" fails unless the registry holds exactly this node set (count and fingerprint)
 *   TIMELOCK_SALT, WAIT_FOR_DELAY, DRY_RUN  as in scripts/gov/safe-exec.ts
 *   REGISTER_OUT     write a JSON result (operation, tx hashes, gas, per-node status) to this path
 *
 * Usage:
 *   NODES_FILE=nodes.json OWNER_KEYS_FILE=keys.json npx hardhat run scripts/gov/register-nodes.ts --network <net>
 */

import { ethers, network } from "hardhat";
import * as fs from "fs";
import * as path from "path";
import {
  envAddress,
  envFlag,
  executeThroughTimelock,
  loadOwnerKeys,
  readJsonObject,
  requireEnv,
  type SafeCall,
  type TimelockResult,
} from "./safe";

// A node url rides in the Sphinx routing header: nox rejects it when 34 + len > 128 (SHIFT_SIZE), so 94 bytes.
const MAX_URL_BYTES = 94;
const ROLE_NAMES: Record<number, string> = { 1: "relay", 2: "exit", 3: "full" };
const STATUS_REGISTERED = 1n;

interface NodeSpec {
  readonly name: string;
  readonly address: string;
  readonly sphinxKey: string;
  readonly url: string;
  readonly ingressUrl: string;
  readonly metadataUrl: string;
  readonly role: number;
}

interface NodeState {
  readonly node: NodeSpec;
  readonly registered: boolean;
  readonly mismatches: readonly string[];
}

function parseNodes(file: string, chainId: bigint): NodeSpec[] {
  const parsed = readJsonObject(file, "NODES_FILE");
  if (
    parsed.chainId !== undefined &&
    BigInt(String(parsed.chainId)) !== chainId
  ) {
    throw new Error(
      `NODES_FILE is for chainId ${parsed.chainId}, but ${network.name} is chainId ${chainId}.`,
    );
  }
  if (!Array.isArray(parsed.nodes) || parsed.nodes.length === 0) {
    throw new Error(`NODES_FILE ${file} needs a non-empty "nodes" array.`);
  }
  const addresses = new Set<string>();
  const keys = new Set<string>();
  return parsed.nodes.map((entry: unknown, index: number) => {
    if (typeof entry !== "object" || entry === null) {
      throw new Error(`NODES_FILE nodes[${index}] must be an object.`);
    }
    const raw = entry as Record<string, unknown>;
    const name = typeof raw.name === "string" ? raw.name : `nodes[${index}]`;
    const where = `NODES_FILE ${name}`;
    if (typeof raw.address !== "string" || !ethers.isAddress(raw.address)) {
      throw new Error(`${where}: address is not a valid address.`);
    }
    const address = ethers.getAddress(raw.address);
    if (address === ethers.ZeroAddress) {
      throw new Error(`${where}: address must be non-zero.`);
    }
    if (
      typeof raw.sphinxKey !== "string" ||
      !/^0x[0-9a-fA-F]{64}$/.test(raw.sphinxKey)
    ) {
      throw new Error(`${where}: sphinxKey must be 0x + 64 hex characters.`);
    }
    const sphinxKey = raw.sphinxKey.toLowerCase();
    if (BigInt(sphinxKey) === 0n) {
      throw new Error(`${where}: sphinxKey must be non-zero.`);
    }
    if (typeof raw.url !== "string" || raw.url === "") {
      throw new Error(`${where}: url must be a non-empty multiaddr.`);
    }
    if (!/^\/ip[46]\//.test(raw.url)) {
      throw new Error(
        `${where}: url ${raw.url} must be an /ip4/ or /ip6/ multiaddr; nodes do not dial /dns addresses.`,
      );
    }
    if (Buffer.byteLength(raw.url, "utf8") > MAX_URL_BYTES) {
      throw new Error(
        `${where}: url is ${Buffer.byteLength(raw.url, "utf8")} bytes; the Sphinx header fits ${MAX_URL_BYTES}.`,
      );
    }
    if (!raw.url.includes("/p2p/")) {
      console.log(
        `  WARNING: ${name} url has no /p2p/<PeerId>; peers cannot authenticate the dial.`,
      );
    }
    const ingressUrl = raw.ingressUrl ?? "";
    const metadataUrl = raw.metadataUrl ?? "";
    if (typeof ingressUrl !== "string" || typeof metadataUrl !== "string") {
      throw new Error(`${where}: ingressUrl and metadataUrl must be strings.`);
    }
    if (ingressUrl !== "" && !/^https?:\/\/[^\s]+$/.test(ingressUrl)) {
      throw new Error(
        `${where}: ingressUrl ${ingressUrl} is not an http(s) URL.`,
      );
    }
    const role = raw.role;
    if (typeof role !== "number" || ROLE_NAMES[role] === undefined) {
      throw new Error(
        `${where}: role must be 1 (relay), 2 (exit) or 3 (full).`,
      );
    }
    if (addresses.has(address)) {
      throw new Error(`${where}: address ${address} is listed twice.`);
    }
    if (keys.has(sphinxKey)) {
      throw new Error(`${where}: sphinxKey ${sphinxKey} is listed twice.`);
    }
    addresses.add(address);
    keys.add(sphinxKey);
    return {
      name,
      address,
      sphinxKey,
      url: raw.url,
      ingressUrl,
      metadataUrl,
      role,
    };
  });
}

function expectedFingerprint(nodes: readonly NodeSpec[]): string {
  let acc = 0n;
  for (const node of nodes) {
    acc ^= BigInt(ethers.solidityPackedKeccak256(["address"], [node.address]));
  }
  return ethers.toBeHex(acc, 32);
}

async function main(): Promise<void> {
  const [submitter] = await ethers.getSigners();
  const chainId = (await ethers.provider.getNetwork()).chainId;
  const nodes = parseNodes(requireEnv("NODES_FILE"), chainId);
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
  const govSafe = envAddress("GOV_SAFE", governance.govSafe);
  const timelock = envAddress("TIMELOCK", governance.timelock);
  const registryAddress = envAddress("NOX_REGISTRY", contracts.noxRegistry);
  const reregister = envFlag("REREGISTER_MISMATCHED", false);
  const exactSet = envFlag("EXPECT_EXACT_SET", false);
  const dryRun = envFlag("DRY_RUN", false);

  if ((await ethers.provider.getCode(registryAddress)) === "0x") {
    throw new Error(
      `NoxRegistry ${registryAddress} has no code on ${network.name}.`,
    );
  }
  const registry = await ethers.getContractAt("NoxRegistry", registryAddress);

  console.log(`NoxRegistry privileged registration (${nodes.length} nodes)`);
  console.log(`  Network:   ${network.name} (chainId: ${chainId})`);
  console.log(`  Registry:  ${registryAddress}`);
  console.log(`  Timelock:  ${timelock}`);
  console.log(`  Gov Safe:  ${govSafe}`);
  console.log(`  Submitter: ${submitter.address}`);

  const readState = async (node: NodeSpec): Promise<NodeState> => {
    const row = await registry.relayers(node.address);
    if (!row.isRegistered) return { node, registered: false, mismatches: [] };
    const mismatches: string[] = [];
    if (row.sphinxKey.toLowerCase() !== node.sphinxKey) {
      mismatches.push(`sphinxKey ${row.sphinxKey}`);
    }
    if (row.url !== node.url) mismatches.push(`url ${row.url}`);
    if (row.ingressUrl !== node.ingressUrl) {
      mismatches.push(`ingressUrl "${row.ingressUrl}"`);
    }
    if (row.metadataUrl !== node.metadataUrl) {
      mismatches.push(`metadataUrl "${row.metadataUrl}"`);
    }
    const role = Number(await registry.nodeRoles(node.address));
    if (role !== node.role) mismatches.push(`role ${role}`);
    if (row.status !== STATUS_REGISTERED) {
      mismatches.push(`status ${row.status}`);
    }
    if (row.frozen) mismatches.push("frozen");
    return { node, registered: true, mismatches };
  };

  const before = await Promise.all(nodes.map(readState));
  const replace = before.filter((s) => s.registered && s.mismatches.length > 0);
  const missing = before.filter((s) => !s.registered);
  for (const s of replace) {
    console.log(
      `  ${reregister ? "REPLACE" : "MISMATCH"} ${s.node.name} ${s.node.address}: on-chain ${s.mismatches.join(", ")}`,
    );
  }

  const unregistering = new Set(
    reregister ? replace.map((s) => s.node.address) : [],
  );
  const toRegister = [...missing, ...(reregister ? replace : [])];
  for (const s of toRegister) {
    const owner = ethers.getAddress(
      await registry.sphinxKeyOwner(s.node.sphinxKey),
    );
    if (
      owner !== ethers.ZeroAddress &&
      owner !== s.node.address &&
      !unregistering.has(owner)
    ) {
      throw new Error(
        `${s.node.name}: sphinxKey ${s.node.sphinxKey} is already registered to ${owner}; registerPrivileged would revert DuplicateKey.`,
      );
    }
  }

  const calls: SafeCall[] = [
    ...[...unregistering].map((address) => ({
      to: registryAddress,
      value: 0n,
      data: registry.interface.encodeFunctionData("forceUnregister", [address]),
    })),
    ...toRegister.map(({ node }) => ({
      to: registryAddress,
      value: 0n,
      data: registry.interface.encodeFunctionData("registerPrivileged", [
        node.address,
        node.sphinxKey,
        node.url,
        node.ingressUrl,
        node.metadataUrl,
        node.role,
      ]),
    })),
  ];
  console.log(
    `  Plan: ${missing.length} to register, ${unregistering.size} to replace, ${nodes.length - missing.length - replace.length} already correct.`,
  );

  let result: TimelockResult | null = null;
  if (calls.length > 0) {
    const countBefore = await registry.relayerCount();
    const fingerprintBefore = await registry.topologyFingerprint();
    const saltRaw = process.env.TIMELOCK_SALT;
    const salt =
      saltRaw !== undefined && saltRaw.trim() !== ""
        ? ethers.zeroPadValue(saltRaw.trim(), 32)
        : ethers.keccak256(
            ethers.AbiCoder.defaultAbiCoder().encode(
              ["string", "bytes32", "uint256", "bytes[]"],
              [
                "hisoka.nox.register-nodes",
                fingerprintBefore,
                countBefore,
                calls.map((call) => call.data),
              ],
            ),
          );
    result = await executeThroughTimelock({
      safe: govSafe,
      timelock,
      batch: { calls, predecessor: ethers.ZeroHash, salt },
      keys: loadOwnerKeys(requireEnv("OWNER_KEYS_FILE")),
      submitter,
      dryRun,
      waitForDelay: envFlag("WAIT_FOR_DELAY", true),
      label: "register-nodes",
      log: (line) => console.log(line),
    });
    console.log(
      `  Outcome: ${result.outcome} (operation ${result.operationId})`,
    );
    if (result.outcome === "dry-run" || result.outcome === "scheduled") {
      return;
    }
  }

  console.log();
  console.log("Verification");
  const after = await Promise.all(nodes.map(readState));
  const failures: string[] = [];
  for (const s of after) {
    const active = await registry.isActiveRelayer(s.node.address);
    const ok = s.registered && s.mismatches.length === 0 && active;
    console.log(
      `  [${ok ? "ok" : "FAIL"}] ${s.node.name.padEnd(12)} ${s.node.address} ${ROLE_NAMES[s.node.role].padEnd(5)} ${s.node.url}` +
        (s.node.ingressUrl === "" ? "" : ` ingress ${s.node.ingressUrl}`) +
        (ok
          ? ""
          : ` (${s.registered ? s.mismatches.join(", ") || "inactive" : "not registered"})`),
    );
    if (!ok) failures.push(s.node.name);
  }
  const relayerCount = await registry.relayerCount();
  const fingerprint = await registry.topologyFingerprint();
  const expected = expectedFingerprint(nodes);
  const paused = await registry.paused();
  console.log(`  relayerCount:        ${relayerCount}`);
  console.log(`  topologyFingerprint: ${fingerprint}`);
  console.log(`  node-set XOR:        ${expected}`);
  console.log(`  paused:              ${paused}`);
  if (paused) failures.push("registry is paused");
  const exact =
    relayerCount === BigInt(nodes.length) && fingerprint === expected;
  if (!exact) {
    const note = `registry holds ${relayerCount} nodes and fingerprint ${fingerprint}; this node set is ${nodes.length} nodes with XOR ${expected}`;
    if (exactSet) failures.push(note);
    else console.log(`  NOTE: ${note}.`);
  }

  if (
    process.env.REGISTER_OUT !== undefined &&
    process.env.REGISTER_OUT !== ""
  ) {
    const out = {
      network: network.name,
      chainId: Number(chainId),
      registry: registryAddress,
      timelock,
      govSafe,
      operationId: result?.operationId ?? null,
      outcome: result?.outcome ?? "nothing-to-do",
      transactions: (result?.safeExecutions ?? []).map((execution) => ({
        safeTxHash: execution.safeTxHash,
        txHash: execution.txHash,
        gasUsed: execution.gasUsed.toString(),
      })),
      relayerCount: relayerCount.toString(),
      topologyFingerprint: fingerprint,
      nodeSetFingerprint: expected,
      paused,
      nodes: after.map((s) => ({
        name: s.node.name,
        address: s.node.address,
        role: s.node.role,
        registered: s.registered,
        mismatches: s.mismatches,
      })),
    };
    fs.writeFileSync(process.env.REGISTER_OUT, JSON.stringify(out, null, 2));
    console.log(`  Result: ${process.env.REGISTER_OUT}`);
  }

  if (failures.length > 0) {
    throw new Error(`verification failed: ${failures.join("; ")}`);
  }
  console.log("  All nodes registered and active.");
}

if (require.main === module) {
  main()
    .then(() => process.exit(0))
    .catch((error) => {
      console.error(error);
      process.exit(1);
    });
}
