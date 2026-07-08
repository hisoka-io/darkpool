#!/usr/bin/env node
/**
 * CLI Proof Generator using bb.js
 *
 * This script generates ZK proofs using the same bb.js library as the deployed verifiers,
 * ensuring VK hash compatibility.
 *
 * Usage: node prove_cli.mjs <circuit_name> <inputs_json_file> <output_dir>
 *
 * Example: node prove_cli.mjs deposit inputs.json ./output
 *
 * Output files:
 *   - proof.bin: Raw proof bytes
 *   - public_inputs.json: Array of hex strings
 *   - result.json: { success, proof_hex, public_inputs, error? }
 */

import { UltraHonkBackend, Barretenberg } from "@aztec/bb.js";
import { Noir } from "@noir-lang/noir_js";
import { readFileSync, writeFileSync, mkdirSync } from "fs";
import { resolve, dirname } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));

async function main() {
  const args = process.argv.slice(2);

  if (args.length < 3) {
    console.error(
      "Usage: prove_cli.mjs <circuit_name> <inputs_json_file> <output_dir>",
    );
    process.exit(1);
  }

  const [circuitName, inputsFile, outputDir] = args;

  try {
    mkdirSync(outputDir, { recursive: true });

    const circuitPath = resolve(
      __dirname,
      `../../circuits/target/${circuitName}.json`,
    );
    const circuitJson = JSON.parse(readFileSync(circuitPath, "utf8"));

    const inputs = JSON.parse(readFileSync(inputsFile, "utf8"));

    const threads = parseInt(process.env.BB_THREADS ?? "16", 10);
    const api = await Barretenberg.new({ threads });
    const noir = new Noir(circuitJson);
    const backend = new UltraHonkBackend(circuitJson.bytecode, api);

    const { witness } = await noir.execute(inputs);

    const { proof, publicInputs } = await backend.generateProof(witness, {
      verifierTarget: "evm",
    });

    const verified = await backend.verifyProof(
      { proof, publicInputs },
      { verifierTarget: "evm" },
    );

    const publicInputsHex = publicInputs.map((x) => {
      const hexVal = BigInt(x.toString()).toString(16).padStart(64, "0");
      return "0x" + hexVal;
    });

    writeFileSync(resolve(outputDir, "proof.bin"), Buffer.from(proof));
    writeFileSync(
      resolve(outputDir, "public_inputs.json"),
      JSON.stringify(publicInputsHex, null, 2),
    );

    const result = {
      success: true,
      verified,
      proof_hex: "0x" + Buffer.from(proof).toString("hex"),
      proof_size: proof.length,
      public_inputs: publicInputsHex,
      public_inputs_count: publicInputs.length,
    };

    writeFileSync(
      resolve(outputDir, "result.json"),
      JSON.stringify(result, null, 2),
    );

    console.log(JSON.stringify(result));

    await api.destroy();
    process.exit(0);
  } catch (error) {
    const result = {
      success: false,
      error: error?.message ?? String(error),
      stack: error?.stack ?? "",
    };

    writeFileSync(
      resolve(outputDir, "result.json"),
      JSON.stringify(result, null, 2),
    );
    console.error(JSON.stringify(result));
    process.exit(1);
  }
}

main();
