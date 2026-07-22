import { generateProof } from "../prover-base.js";
import { circuit } from "../generated/split_circuit.js";
import { SplitInputs, ProofData } from "../types.js";
import { marshalNote, pointHex } from "../marshal.js";

export async function proveSplit(inputs: SplitInputs): Promise<ProofData> {
  const c = pointHex(inputs.compliancePk);
  return generateProof("split", circuit, {
    compliance_pubkey_x: c.x,
    compliance_pubkey_y: c.y,
    note_in: marshalNote("split", inputs.noteIn),
    spend_scalar: inputs.spendScalar.toString(),
    index_in: inputs.indexIn.toString(),
    path_in: inputs.pathIn.map((p) => p.toString()),
    note_out_1: marshalNote("split", inputs.noteOut1),
    eph_1: inputs.eph1.toString(),
    note_out_2: marshalNote("split", inputs.noteOut2),
    eph_2: inputs.eph2.toString(),
  });
}
