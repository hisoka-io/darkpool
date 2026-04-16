import { generateProof } from "../prover-base.js";
import { circuit } from "../generated/gas_payment_circuit.js";
import { GasPaymentInputs, ProofData } from "../types.js";

export async function proveGasPayment(inputs: GasPaymentInputs): Promise<ProofData> {
  const noirInputs = {
    merkle_root: inputs.merkleRoot.toString(),
    current_timestamp: inputs.currentTimestamp.toString(),
    payment_value: inputs.paymentValue.toString(),
    payment_asset_id: inputs.paymentAssetId.toString(),
    _relayer_address: inputs.relayerAddress.toString(),
    _execution_hash: inputs.executionHash.toString(),
    compliance_pubkey_x: `0x${inputs.compliancePk[0].toString(16)}`,
    compliance_pubkey_y: `0x${inputs.compliancePk[1].toString(16)}`,
    old_note: {
      asset_id: inputs.oldNote.asset_id.toString(),
      value: inputs.oldNote.value.toString(),
      secret: inputs.oldNote.secret.toString(),
      nullifier: inputs.oldNote.nullifier.toString(),
      timelock: inputs.oldNote.timelock.toString(),
      hashlock: inputs.oldNote.hashlock.toString(),
    },
    old_shared_secret: inputs.oldSharedSecret.toString(),
    old_note_index: inputs.oldNoteIndex.toString(),
    old_note_path: inputs.oldNotePath.map((p) => p.toString()),
    hashlock_preimage: inputs.hashlockPreimage.toString(),
    change_note: {
      asset_id: inputs.changeNote.asset_id.toString(),
      value: inputs.changeNote.value.toString(),
      secret: inputs.changeNote.secret.toString(),
      nullifier: inputs.changeNote.nullifier.toString(),
      timelock: inputs.changeNote.timelock.toString(),
      hashlock: inputs.changeNote.hashlock.toString(),
    },
    change_ephemeral_sk: inputs.changeEphemeralSk.toString(),
  };
  return generateProof(circuit, noirInputs);
}
