import { generateProof } from "../prover-base.js";
import { circuit } from "../generated/transfer_circuit.js";
import { TransferInputs, ProofData } from "../types.js";

export async function proveTransfer(inputs: TransferInputs): Promise<ProofData> {
  const noirInputs = {
    merkle_root: inputs.merkleRoot.toString(),
    current_timestamp: inputs.currentTimestamp.toString(),
    compliance_pubkey_x: `0x${inputs.compliancePk[0].toString(16)}`,
    compliance_pubkey_y: `0x${inputs.compliancePk[1].toString(16)}`,
    recipient_B: {
      x: `0x${inputs.recipientB[0].toString(16)}`,
      y: `0x${inputs.recipientB[1].toString(16)}`,
    },
    recipient_P: {
      x: `0x${inputs.recipientP[0].toString(16)}`,
      y: `0x${inputs.recipientP[1].toString(16)}`,
    },
    recipient_proof: {
      U: {
        x: `0x${inputs.recipientProof.U[0].toString(16)}`,
        y: `0x${inputs.recipientProof.U[1].toString(16)}`,
      },
      V: {
        x: `0x${inputs.recipientProof.V[0].toString(16)}`,
        y: `0x${inputs.recipientProof.V[1].toString(16)}`,
      },
      z: `0x${inputs.recipientProof.z.toString(16)}`,
    },
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
    memo_note: {
      asset_id: inputs.memoNote.asset_id.toString(),
      value: inputs.memoNote.value.toString(),
      secret: inputs.memoNote.secret.toString(),
      nullifier: inputs.memoNote.nullifier.toString(),
      timelock: inputs.memoNote.timelock.toString(),
      hashlock: inputs.memoNote.hashlock.toString(),
    },
    memo_ephemeral_sk: inputs.memoEphemeralSk.toString(),
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
