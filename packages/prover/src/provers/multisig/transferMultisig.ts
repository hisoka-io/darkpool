import { Fr } from "@aztec/foundation/fields";
import { Point } from "@zk-kit/baby-jubjub";
import { generateProof } from "../prover-base.js";
import { circuit } from "../generated/transfer_multisig_circuit.js";
import { NoteInput, ProofData } from "../types.js";
import { marshalNote, pointHex } from "../marshal.js";

export interface TransferMultisigInputs {
  compliancePk: Point<bigint>;

  gpk: Point<bigint>;
  frostR: Point<bigint>;
  frostZ: Fr;

  // recipientInPub is the single owner+view+discovery key; paying a MULTISIG recipient is deferred.
  recipientInPub: Point<bigint>;

  oldNote: NoteInput;
  oldNoteIndex: number;
  oldNotePath: Fr[];

  memoNote: NoteInput;
  memoEph: Fr;

  changeNote: NoteInput;
  changeEph: Fr;
}

export async function proveTransferMultisig(
  inputs: TransferMultisigInputs,
): Promise<ProofData> {
  const c = pointHex(inputs.compliancePk);
  return generateProof("transfer_multisig", circuit, {
    compliance_pubkey_x: c.x,
    compliance_pubkey_y: c.y,
    gpk: pointHex(inputs.gpk),
    frost_r: pointHex(inputs.frostR),
    frost_z: inputs.frostZ.toString(),
    recipient_in_pub: pointHex(inputs.recipientInPub),
    old_note: marshalNote("transfer_multisig", inputs.oldNote),
    old_note_index: inputs.oldNoteIndex.toString(),
    old_note_path: inputs.oldNotePath.map((p) => p.toString()),
    memo_note: marshalNote("transfer_multisig", inputs.memoNote),
    memo_eph: inputs.memoEph.toString(),
    change_note: marshalNote("transfer_multisig", inputs.changeNote),
    change_eph: inputs.changeEph.toString(),
  });
}
