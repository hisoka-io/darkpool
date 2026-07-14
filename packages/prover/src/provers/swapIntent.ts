import { UltraHonkBackend } from "@aztec/bb.js";
import { CompiledCircuit, InputMap, Noir } from "@noir-lang/noir_js";
import { Buffer } from "node:buffer";
import { circuit } from "../generated/swap_intent_circuit.js";
import { SwapIntentInputs, SwapIntentProof } from "../types.js";
import { marshalNote, pointHex } from "../marshal.js";
import { ProofError } from "../errors.js";
import { ensureBBInitialized } from "../prover-base.js";
import { INTENT_PI_LEN, INTENT_PROOF_LEN, INTENT_VK_LEN } from "../config.js";

// The taker proves swap_intent client-side on bb.js. verifierTarget 'noir-recursive' emits a proof + VK the outer
// swap_settle circuit consumes via std::verify_proof_with_type; generateRecursiveProofArtifacts splits the VK into
// field elements and returns its hash (the value pinned by INTENT_VK_HASH).
const RECURSIVE = { verifierTarget: "noir-recursive" } as const;

export async function proveSwapIntent(
  inputs: SwapIntentInputs,
): Promise<SwapIntentProof> {
  const c = pointHex(inputs.compliancePk);
  const noirInputs: InputMap = {
    compliance_pubkey_x: c.x,
    compliance_pubkey_y: c.y,
    note_in: marshalNote("swap_intent", inputs.noteIn),
    spend_scalar: inputs.spendScalar.toString(),
    index_in: inputs.indexIn.toString(),
    path_in: inputs.pathIn.map((p) => p.toString()),
    change_note: marshalNote("swap_intent", inputs.changeNote),
    change_eph: inputs.changeEph.toString(),
    received_note: marshalNote("swap_intent", inputs.receivedNote),
    received_eph: inputs.receivedEph.toString(),
    to_asset: inputs.toAsset.toString(),
    from_amount: inputs.fromAmount.toString(),
    expiry: inputs.expiry.toString(),
  };

  const api = await ensureBBInitialized();
  const backend = new UltraHonkBackend(
    (circuit as CompiledCircuit).bytecode,
    api,
  );

  try {
    const { witness } = await new Noir(circuit as CompiledCircuit).execute(
      noirInputs,
    );
    const { proof, publicInputs } = await backend.generateProof(
      witness,
      RECURSIVE,
    );
    const verified = await backend.verifyProof(
      { proof, publicInputs },
      RECURSIVE,
    );
    const art = await backend.generateRecursiveProofArtifacts(
      proof,
      publicInputs.length,
      RECURSIVE,
    );

    const proofAsFields: string[] = [];
    for (let i = 0; i < proof.length; i += 32) {
      proofAsFields.push(
        "0x" + Buffer.from(proof.slice(i, i + 32)).toString("hex"),
      );
    }

    // The recursion ABI freezes these widths (swap_settle declares [Field; N] params); a drift means the outer
    // circuit can no longer consume this proof.
    if (
      art.vkAsFields.length !== INTENT_VK_LEN ||
      proofAsFields.length !== INTENT_PROOF_LEN ||
      publicInputs.length !== INTENT_PI_LEN
    ) {
      throw new ProofError(
        "swap_intent",
        `recursion width drift: vk=${art.vkAsFields.length} proof=${proofAsFields.length} pi=${publicInputs.length}`,
      );
    }

    return {
      proof,
      proofAsFields,
      publicInputs,
      vkAsFields: art.vkAsFields,
      vkHash: art.vkHash,
      verified,
    };
  } catch (err) {
    throw new ProofError(
      "swap_intent",
      err instanceof Error ? err.message : String(err),
      err,
    );
  }
}
