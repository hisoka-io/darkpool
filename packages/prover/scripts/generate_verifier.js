import { UltraHonkBackend, Barretenberg } from "@aztec/bb.js";
import { readFileSync, writeFileSync, existsSync, mkdirSync } from "fs";
import { resolve, dirname } from "path";
import { fileURLToPath } from "url";
import { CIRCUITS } from "./circuits.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const circuitPackagesNames = CIRCUITS.map((c) => c.name);
const circuitsDir = resolve(__dirname, "../../circuits");
const artifactsPath = circuitPackagesNames.map((circuitPackageName) =>
  resolve(circuitsDir, "target", `${circuitPackageName}.json`),
);

const contractsDir = resolve(__dirname, "../../evm-contracts/contracts");
const verifiersDir = resolve(contractsDir, "verifiers");
const outputPath = CIRCUITS.map((c) => resolve(verifiersDir, c.verifier));
const vkHashManifestPath = resolve(verifiersDir, "vk-hashes.json");
const vkHashes = {};

async function main() {
  console.log("--- Generating Solidity Verifiers ---");

  for (
    let circuitIndex = 0;
    circuitIndex < circuitPackagesNames.length;
    circuitIndex++
  ) {
    const artifactPath = artifactsPath[circuitIndex];
    if (!existsSync(artifactPath)) {
      console.error(`[Error] Circuit artifact not found at ${artifactPath}.`);
      console.error(
        'Please run "pnpm build" in the "prover" package first to compile the circuit.',
      );
      process.exit(1);
    }

    const circuitJson = JSON.parse(readFileSync(artifactPath, "utf8"));
    const api = await Barretenberg.new({ threads: 8 });
    const backend = new UltraHonkBackend(circuitJson.bytecode, api);

    try {
      const verificationKey = await backend.getVerificationKey({
        verifierTarget: "evm",
      });
      const verifierString = await backend.getSolidityVerifier(
        verificationKey,
        { verifierTarget: "evm" },
      );

      const vkHashMatch = verifierString.match(
        /uint256 constant VK_HASH = (0x[0-9a-fA-F]{64});/,
      );
      if (!vkHashMatch) {
        console.error(
          `[Error] VK_HASH not found in the generated verifier for "${circuitPackagesNames[circuitIndex]}".`,
        );
        process.exit(1);
      }
      vkHashes[circuitPackagesNames[circuitIndex]] = vkHashMatch[1];

      console.log(`Writing ${outputPath[circuitIndex]}...`);

      if (!existsSync(verifiersDir)) {
        mkdirSync(verifiersDir, { recursive: true });
      }
      writeFileSync(outputPath[circuitIndex], verifierString);
    } catch (error) {
      console.error("[Error] Failed to generate Solidity Verifier:", error);
      process.exit(1);
    } finally {
      await api.destroy();
    }
  }

  writeFileSync(vkHashManifestPath, JSON.stringify(vkHashes, null, 2) + "\n");
  console.log(`Wrote VK-hash manifest: ${vkHashManifestPath}`);
}

main();
