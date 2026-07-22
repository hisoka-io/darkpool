import { generateProof } from "../../prover-base.js";
import { circuit } from "../../generated/transfer_circuit.js";
import { TransferInputs, ProofData } from "../../types.js";
import { marshalNote, pointHex } from "../../marshal.js";

export async function proveTransfer(
  inputs: TransferInputs,
): Promise<ProofData> {
  const c = pointHex(inputs.compliancePk);
  return generateProof("transfer", circuit, {
    compliance_pubkey_x: c.x,
    compliance_pubkey_y: c.y,
    recipient_in_pub: pointHex(inputs.recipientInPub),
    old_note: marshalNote("transfer", inputs.oldNote),
    spend_scalar: inputs.spendScalar.toString(),
    old_note_index: inputs.oldNoteIndex.toString(),
    old_note_path: inputs.oldNotePath.map((p) => p.toString()),
    memo_note: marshalNote("transfer", inputs.memoNote),
    memo_eph: inputs.memoEph.toString(),
    change_note: marshalNote("transfer", inputs.changeNote),
    change_eph: inputs.changeEph.toString(),
  });
}
