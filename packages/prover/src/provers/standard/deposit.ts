import { generateProof } from "../../prover-base.js";
import { circuit } from "../../generated/deposit_circuit.js";
import { DepositInputs, ProofData } from "../../types.js";
import { marshalNote, pointHex } from "../../marshal.js";

export async function proveDeposit(inputs: DepositInputs): Promise<ProofData> {
  const c = pointHex(inputs.compliancePk);
  return generateProof("deposit", circuit, {
    compliance_pubkey_x: c.x,
    compliance_pubkey_y: c.y,
    note: marshalNote("deposit", inputs.note),
    eph: inputs.eph.toString(),
  });
}
