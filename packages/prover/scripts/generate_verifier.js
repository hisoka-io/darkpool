import { UltraHonkBackend, Barretenberg } from "@aztec/bb.js";
import { readFileSync, writeFileSync, existsSync, mkdirSync } from "fs";
import { resolve, dirname } from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const circuitPackagesNames = [
  "deposit",
  "withdraw",
  "transfer",
  "join",
  "split",
  "public_claim",
  "gas_payment",
];
const circuitsDir = resolve(__dirname, "../../circuits");
const artifactsPath = circuitPackagesNames.map((circuitPackageName) =>
  resolve(circuitsDir, "target", `${circuitPackageName}.json`),
);

const contractsDir = resolve(__dirname, "../../evm-contracts/contracts");
const verifiersDir = resolve(contractsDir, "verifiers");
const outputPath = [
  resolve(verifiersDir, "DepositVerifier.sol"),
  resolve(verifiersDir, "WithdrawVerifier.sol"),
  resolve(verifiersDir, "TransferVerifier.sol"),
  resolve(verifiersDir, "JoinVerifier.sol"),
  resolve(verifiersDir, "SplitVerifier.sol"),
  resolve(verifiersDir, "PublicClaimVerifier.sol"),
  resolve(verifiersDir, "GasPaymentVerifier.sol"),
];

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
        verifierTarget: "evm-no-zk",
      });
      const verifierString = await backend.getSolidityVerifier(
        verificationKey,
        { verifierTarget: "evm-no-zk" },
      );

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
}

main();
