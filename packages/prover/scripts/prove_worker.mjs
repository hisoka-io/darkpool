#!/usr/bin/env node
/**
 * Persistent Prover Worker
 *
 * Startup:
 *   Worker prints: {"status":"ready"}\n
 *
 * Prove request:
 *   Client sends: {"cmd":"prove","circuit":"deposit","inputs":{...}}\n
 *   Worker prints: {"success":true,"proof_hex":"0x...","public_inputs":[...]}\n
 *   Or on error:  {"success":false,"error":"message"}\n
 *
 * Shutdown:
 *   Client sends: {"cmd":"shutdown"}\n
 *   Worker exits cleanly.
 *
 * Environment variables:
 *   BB_THREADS   — Number of Barretenberg threads (default: 16)
 *   SKIP_VERIFY  — Set to "1" to skip redundant native proof verification.
 *                  The on-chain Solidity UltraHonkVerifier still verifies.
 */

import { UltraHonkBackend, Barretenberg } from "@aztec/bb.js";
import { Noir } from "@noir-lang/noir_js";
import { readFileSync } from "fs";
import { resolve, dirname } from "path";
import { fileURLToPath } from "url";
import { createInterface } from "readline";

const __dirname = dirname(fileURLToPath(import.meta.url));
const skipVerify = process.env.SKIP_VERIFY === "1";

// don't corrupt the JSON-line protocol on stdout.
console.log = (...args) => process.stderr.write(args.join(" ") + "\n");

function sendResult(obj) {
  process.stdout.write(JSON.stringify(obj) + "\n");
}

async function main() {
  const threads = parseInt(process.env.BB_THREADS ?? "16", 10);
  const api = await Barretenberg.new({ threads });

  const circuitCache = new Map();

  sendResult({ status: "ready" });

  const rl = createInterface({ input: process.stdin, crlfDelay: Infinity });

  for await (const line of rl) {
    if (!line.trim()) continue;

    let cmd;
    try {
      cmd = JSON.parse(line);
    } catch (e) {
      sendResult({ success: false, error: `Invalid JSON: ${e.message}` });
      continue;
    }

    if (cmd.cmd === "shutdown") {
      break;
    }

    if (cmd.cmd !== "prove") {
      sendResult({
        success: false,
        error: `Unknown command: ${cmd.cmd}. Expected "prove" or "shutdown".`,
      });
      continue;
    }

    const { circuit, inputs } = cmd;
    if (!circuit || !inputs) {
      sendResult({
        success: false,
        error: 'Missing "circuit" or "inputs" field in prove command.',
      });
      continue;
    }

    try {
      // Get or create cached circuit artifacts
      if (!circuitCache.has(circuit)) {
        const circuitPath = resolve(
          __dirname,
          `../../circuits/target/${circuit}.json`,
        );
        const circuitJson = JSON.parse(readFileSync(circuitPath, "utf8"));
        const noir = new Noir(circuitJson);
        const backend = new UltraHonkBackend(circuitJson.bytecode, api);
        circuitCache.set(circuit, { noir, backend });
      }

      const { noir, backend } = circuitCache.get(circuit);

      // Execute circuit witness
      const { witness } = await noir.execute(inputs);

      // Generate proof
      const { proof, publicInputs } = await backend.generateProof(witness, {
        verifierTarget: "evm",
      });

      let verified = true;
      if (!skipVerify) {
        verified = await backend.verifyProof(
          { proof, publicInputs },
          { verifierTarget: "evm" },
        );
      }

      const publicInputsHex = publicInputs.map((x) => {
        const hexVal = BigInt(x.toString()).toString(16).padStart(64, "0");
        return "0x" + hexVal;
      });

      sendResult({
        success: true,
        verified,
        proof_hex: "0x" + Buffer.from(proof).toString("hex"),
        proof_size: proof.length,
        public_inputs: publicInputsHex,
        public_inputs_count: publicInputs.length,
      });
    } catch (error) {
      sendResult({
        success: false,
        error: error?.message ?? String(error),
        stack: error?.stack ?? "",
      });
    }
  }

  await api.destroy();
  process.exit(0);
}

main().catch((e) => {
  process.stderr.write(`prove_worker fatal: ${e.message}\n`);
  process.exit(1);
});
