import { ethers } from "hardhat";
import { readFileSync } from "node:fs";

interface RegistrationNode {
  readonly address: string;
  readonly sphinxKey: string;
  readonly url: string;
  readonly ingressUrl: string;
  readonly metadataUrl: string;
  readonly role: number;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function stringField(record: Record<string, unknown>, key: string): string {
  const value = record[key];
  if (typeof value !== "string") {
    throw new Error(`registration manifest ${key} must be a string`);
  }
  return value;
}

function numberField(record: Record<string, unknown>, key: string): number {
  const value = record[key];
  if (typeof value !== "number" || !Number.isSafeInteger(value)) {
    throw new Error(`registration manifest ${key} must be a safe integer`);
  }
  return value;
}

async function main(): Promise<void> {
  const manifestPath = process.env["REGISTRATION_MANIFEST_PATH"];
  const deploymentPath = process.env["DEPLOYMENT_RECORD_PATH"];
  if (!manifestPath || !deploymentPath) {
    throw new Error(
      "REGISTRATION_MANIFEST_PATH and DEPLOYMENT_RECORD_PATH are required",
    );
  }
  const decoded: unknown = JSON.parse(readFileSync(manifestPath, "utf8"));
  const deployment: unknown = JSON.parse(readFileSync(deploymentPath, "utf8"));
  if (!isRecord(decoded) || decoded["kind"] !== "registration_required") {
    throw new Error("registration manifest kind is invalid");
  }
  if (
    !isRecord(deployment) ||
    !isRecord(deployment["governance"]) ||
    !isRecord(deployment["contracts"])
  ) {
    throw new Error("deployment record is incomplete");
  }
  const rawNodes = decoded["nodes"];
  if (!Array.isArray(rawNodes) || rawNodes.length !== 3) {
    throw new Error("registration manifest must contain exactly three nodes");
  }
  const nodes = rawNodes.map((node, index): RegistrationNode => {
    if (!isRecord(node))
      throw new Error(`registration node ${index} is invalid`);
    return {
      address: stringField(node, "address"),
      sphinxKey: `0x${stringField(node, "sphinxKey").replace(/^0x/u, "")}`,
      url: stringField(node, "url"),
      ingressUrl: stringField(node, "ingressUrl"),
      metadataUrl: stringField(node, "metadataUrl"),
      role: numberField(node, "role"),
    };
  });
  const governance = deployment["governance"];
  const contracts = deployment["contracts"];
  const timelock = stringField(governance, "timelock");
  const registryAddress = stringField(contracts, "noxRegistry");
  if (
    ethers.getAddress(registryAddress) !==
    ethers.getAddress(stringField(decoded, "registryAddress"))
  ) {
    throw new Error("registration manifest targets a different NoxRegistry");
  }
  if (
    BigInt(numberField(decoded, "chainId")) !==
    (await ethers.provider.getNetwork()).chainId
  ) {
    throw new Error("registration manifest targets a different chain");
  }

  await ethers.provider.send("anvil_impersonateAccount", [timelock]);
  await ethers.provider.send("anvil_setBalance", [
    timelock,
    "0x56BC75E2D63100000",
  ]);
  try {
    const registry = await ethers.getContractAt(
      "NoxRegistry",
      registryAddress,
      await ethers.getSigner(timelock),
    );
    for (const node of nodes) {
      await (
        await registry.registerPrivileged(
          node.address,
          node.sphinxKey,
          node.url,
          node.ingressUrl,
          node.metadataUrl,
          node.role,
        )
      ).wait();
    }
    const expectedFingerprint = `0x${stringField(
      decoded,
      "topologyFingerprint",
    ).replace(/^0x/u, "")}`;
    if ((await registry.topologyFingerprint()) !== expectedFingerprint) {
      throw new Error(
        "registered topology fingerprint does not match the fixture",
      );
    }
    if ((await registry.relayerCount()) !== BigInt(nodes.length)) {
      throw new Error("registered relayer count does not match the fixture");
    }
  } finally {
    await ethers.provider.send("anvil_stopImpersonatingAccount", [timelock]);
  }
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : String(error);
  console.error(message);
  process.exitCode = 1;
});
