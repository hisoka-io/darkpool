import { generateProof } from "../../prover-base.js";
import { circuit } from "../../generated/join_circuit.js";
import { JoinInputs, ProofData } from "../../types.js";
import { marshalNote, pointHex } from "../../marshal.js";

export async function proveJoin(inputs: JoinInputs): Promise<ProofData> {
  const c = pointHex(inputs.compliancePk);
  return generateProof("join", circuit, {
    compliance_pubkey_x: c.x,
    compliance_pubkey_y: c.y,
    note_a: marshalNote("join", inputs.noteA),
    spend_scalar_a: inputs.spendScalarA.toString(),
    index_a: inputs.indexA.toString(),
    path_a: inputs.pathA.map((p) => p.toString()),
    note_b: marshalNote("join", inputs.noteB),
    spend_scalar_b: inputs.spendScalarB.toString(),
    index_b: inputs.indexB.toString(),
    path_b: inputs.pathB.map((p) => p.toString()),
    note_out: marshalNote("join", inputs.noteOut),
    eph_out: inputs.ephOut.toString(),
  });
}
