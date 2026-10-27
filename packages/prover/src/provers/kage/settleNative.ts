import { CompiledCircuit, InputMap, Noir } from "@noir-lang/noir_js";
import { execFileSync } from "node:child_process";
import { writeFileSync, readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { Buffer } from "node:buffer";
import { circuit } from "../../generated/swap_settle_circuit.js";
import { SwapSettleInputs, ProofData } from "../../types.js";
import { marshalNote, pointHex } from "../../marshal.js";
import { ProofError } from "../../errors.js";
import {
  BB_NATIVE_PATH,
  BB_NATIVE_VERSION,
  SETTLE_PI_LEN,
  SETTLE_PROOF_FIELDS,
} from "../../config.js";
import { runNative, withSecretWorkdir } from "./secretWorkdir.js";

// swap_settle proves on native bb: verify_proof_with_type is excluded from the bb.js WASM build.
export function assertNativeBb(): void {
  let version: string;
  try {
    version = execFileSync(BB_NATIVE_PATH, ["--version"], {
      encoding: "utf8",
    }).trim();
  } catch (err) {
    throw new ProofError(
      "swap_settle",
      `native bb missing at ${BB_NATIVE_PATH} (set BB_NATIVE_PATH; obtain via bbup)`,
      err,
    );
  }
  if (version !== BB_NATIVE_VERSION) {
    throw new ProofError(
      "swap_settle",
      `native bb version mismatch: got ${version} want ${BB_NATIVE_VERSION}`,
    );
  }
}

// bb prove exits 0 when the circuit is unsatisfied and only verify fails, so the prove log carries the reason.
function proveDiagnostics(log: string): string {
  return log
    .split("\n")
    .filter((line) => /mismatch|failure|failed/i.test(line))
    .map((line) => line.replace(/\s*\(mem: [^)]*\)\s*$/, "").trim())
    .join("; ");
}

/**
 * The native prove without the off-circuit intent-key check, so a test can show the circuit's own pin rejects
 * a foreign key. Kept out of the package barrel: callers use `proveSwapSettle`.
 */
export async function proveSwapSettleNative(
  inputs: SwapSettleInputs,
): Promise<ProofData> {
  assertNativeBb();
  const c = pointHex(inputs.compliancePk);
  const noirInputs: InputMap = {
    compliance_pubkey_x: c.x,
    compliance_pubkey_y: c.y,
    current_timestamp: inputs.currentTimestamp.toString(),
    verification_key: inputs.intent.vkAsFields,
    intent_proof: inputs.intent.proofAsFields,
    intent_public_inputs: inputs.intent.publicInputs,
    maker_note_in: marshalNote("swap_settle", inputs.makerNoteIn),
    maker_spend_scalar: inputs.makerSpendScalar.toString(),
    maker_index: inputs.makerIndex.toString(),
    maker_path: inputs.makerPath.map((p) => p.toString()),
    maker_received: marshalNote("swap_settle", inputs.makerReceived),
    maker_received_eph: inputs.makerReceivedEph.toString(),
    maker_change: marshalNote("swap_settle", inputs.makerChange),
    maker_change_eph: inputs.makerChangeEph.toString(),
  };

  try {
    return await withSecretWorkdir("kage-settle-", async (dir) => {
      const { witness } = await new Noir(circuit as CompiledCircuit).execute(
        noirInputs,
      );
      const witPath = join(dir, "witness.gz");
      const bytecodePath = join(dir, "swap_settle.json");
      const outDir = join(dir, "out");
      writeFileSync(witPath, witness, { mode: 0o600 });
      writeFileSync(bytecodePath, JSON.stringify(circuit));

      let proveLog: string;
      try {
        proveLog = await runNative(BB_NATIVE_PATH, [
          "prove",
          "-b",
          bytecodePath,
          "-w",
          witPath,
          "-o",
          outDir,
          "-t",
          "evm",
          "--write_vk",
        ]);
      } finally {
        rmSync(witPath, { force: true });
      }
      try {
        await runNative(BB_NATIVE_PATH, [
          "verify",
          "-k",
          join(outDir, "vk"),
          "-p",
          join(outDir, "proof"),
          "-i",
          join(outDir, "public_inputs"),
          "-t",
          "evm",
        ]);
      } catch (err) {
        const reason = proveDiagnostics(proveLog);
        throw new ProofError(
          "swap_settle",
          `native verify rejected the settle proof${reason ? `; bb prove reported: ${reason}` : ""}`,
          err,
        );
      }

      const proof = readFileSync(join(outDir, "proof"));
      if (proof.length !== SETTLE_PROOF_FIELDS * 32) {
        throw new ProofError(
          "swap_settle",
          `outer-proof field-count drift: got ${proof.length / 32} want ${SETTLE_PROOF_FIELDS}`,
        );
      }
      const pubsBuf = readFileSync(join(outDir, "public_inputs"));
      const publicInputs: string[] = [];
      for (let i = 0; i < pubsBuf.length; i += 32) {
        publicInputs.push(
          "0x" + Buffer.from(pubsBuf.subarray(i, i + 32)).toString("hex"),
        );
      }
      if (publicInputs.length !== SETTLE_PI_LEN) {
        throw new ProofError(
          "swap_settle",
          `public-input width drift: got ${publicInputs.length} want ${SETTLE_PI_LEN}`,
        );
      }
      return { proof: new Uint8Array(proof), publicInputs, verified: true };
    });
  } catch (err) {
    if (err instanceof ProofError) throw err;
    throw new ProofError(
      "swap_settle",
      err instanceof Error ? err.message : String(err),
      err,
    );
  }
}
