import { CompiledCircuit, InputMap, Noir } from "@noir-lang/noir_js";
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Buffer } from "node:buffer";
import { circuit } from "../generated/swap_settle_circuit.js";
import { SwapSettleInputs, ProofData } from "../types.js";
import { marshalNote, pointHex } from "../marshal.js";
import { ProofError } from "../errors.js";
import {
  BB_NATIVE_PATH,
  BB_NATIVE_VERSION,
  SETTLE_PI_LEN,
  SETTLE_PROOF_FIELDS,
} from "../config.js";

// The maker (a server/solver) proves swap_settle with NATIVE bb: the recursion (std::verify_proof_with_type) is
// excluded from the bb.js WASM build. Witness generation is off bb.js/noir_js; only the prove step shells to the
// matching native bb.
function assertNativeBb(): void {
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
  if (!version.includes(BB_NATIVE_VERSION)) {
    throw new ProofError(
      "swap_settle",
      `native bb version mismatch: got ${version} want ${BB_NATIVE_VERSION}`,
    );
  }
}

export function nativeBbAvailable(): boolean {
  try {
    assertNativeBb();
    return true;
  } catch {
    return false;
  }
}

export async function proveSwapSettle(
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

  const dir = mkdtempSync(join(tmpdir(), "kage-settle-"));
  try {
    const { witness } = await new Noir(circuit as CompiledCircuit).execute(
      noirInputs,
    );
    const witPath = join(dir, "witness.gz");
    const bytecodePath = join(dir, "swap_settle.json");
    const outDir = join(dir, "out");
    writeFileSync(witPath, witness);
    writeFileSync(bytecodePath, JSON.stringify(circuit));

    execFileSync(
      BB_NATIVE_PATH,
      [
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
      ],
      { stdio: "pipe" },
    );
    // Native verify sets `verified` deterministically (exit non-zero throws).
    execFileSync(
      BB_NATIVE_PATH,
      [
        "verify",
        "-k",
        join(outDir, "vk"),
        "-p",
        join(outDir, "proof"),
        "-i",
        join(outDir, "public_inputs"),
        "-t",
        "evm",
      ],
      { stdio: "pipe" },
    );

    const proof = readFileSync(join(outDir, "proof"));
    // SETTLE_PROOF_FIELDS is a frozen recursion-ABI width; a toolchain bump that changes the outer-proof size
    // (as bb 5.0 changed the inner proof 500 -> 458) must fail here, not silently at on-chain verify.
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
  } catch (err) {
    if (err instanceof ProofError) throw err;
    throw new ProofError(
      "swap_settle",
      err instanceof Error ? err.message : String(err),
      err,
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}
