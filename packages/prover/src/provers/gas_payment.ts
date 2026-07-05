import { generateProof } from "../prover-base.js";
import { circuit } from "../generated/gas_payment_circuit.js";
import { GasPaymentInputs, ProofData } from "../types.js";
import { marshalNote, pointHex } from "../marshal.js";

export async function proveGasPayment(
  inputs: GasPaymentInputs,
): Promise<ProofData> {
  const c = pointHex(inputs.compliancePk);
  return generateProof("gas_payment", circuit, {
    current_timestamp: inputs.currentTimestamp.toString(),
    payment_value: inputs.paymentValue.toString(),
    payment_asset_id: inputs.paymentAssetId.toString(),
    _relayer_address: inputs.relayerAddress.toString(),
    _execution_hash: inputs.executionHash.toString(),
    compliance_pubkey_x: c.x,
    compliance_pubkey_y: c.y,
    old_note: marshalNote("gas_payment", inputs.oldNote),
    spend_scalar: inputs.spendScalar.toString(),
    old_note_index: inputs.oldNoteIndex.toString(),
    old_note_path: inputs.oldNotePath.map((p) => p.toString()),
    change_note: marshalNote("gas_payment", inputs.changeNote),
    change_eph: inputs.changeEph.toString(),
  });
}
