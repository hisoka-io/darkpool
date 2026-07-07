import { generateProof } from "../prover-base.js";
import { circuit } from "../generated/withdraw_circuit.js";
import { WithdrawInputs, ProofData } from "../types.js";
import { marshalNote, pointHex } from "../marshal.js";

export async function proveWithdraw(
  inputs: WithdrawInputs,
): Promise<ProofData> {
  const c = pointHex(inputs.compliancePk);
  return generateProof("withdraw", circuit, {
    withdraw_value: inputs.withdrawValue.toString(),
    _recipient: inputs.recipient.toString(),
    _intent_hash: inputs.intentHash.toString(),
    compliance_pubkey_x: c.x,
    compliance_pubkey_y: c.y,
    old_note: marshalNote("withdraw", inputs.oldNote),
    spend_scalar: inputs.spendScalar.toString(),
    old_note_index: inputs.oldNoteIndex.toString(),
    old_note_path: inputs.oldNotePath.map((p) => p.toString()),
    change_note: marshalNote("withdraw", inputs.changeNote),
    change_eph: inputs.changeEph.toString(),
  });
}
