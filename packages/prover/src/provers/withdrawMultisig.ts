import { Fr } from "@aztec/foundation/fields";
import { Point } from "@zk-kit/baby-jubjub";
import { generateProof } from "../prover-base.js";
import { circuit } from "../generated/withdraw_multisig_circuit.js";
import { NoteInput, ProofData } from "../types.js";
import { marshalNote, pointHex } from "../marshal.js";

export interface WithdrawMultisigInputs {
  withdrawValue: Fr;
  recipient: Fr;
  intentHash: Fr;
  compliancePk: Point<bigint>;

  gpk: Point<bigint>;
  frostR: Point<bigint>;
  frostZ: Fr;

  oldNote: NoteInput;
  oldNoteIndex: number;
  oldNotePath: Fr[];

  changeNote: NoteInput;
  changeEph: Fr;
}

export async function proveWithdrawMultisig(
  inputs: WithdrawMultisigInputs,
): Promise<ProofData> {
  const c = pointHex(inputs.compliancePk);
  return generateProof("withdraw_multisig", circuit, {
    withdraw_value: inputs.withdrawValue.toString(),
    recipient: inputs.recipient.toString(),
    intent_hash: inputs.intentHash.toString(),
    compliance_pubkey_x: c.x,
    compliance_pubkey_y: c.y,
    gpk: pointHex(inputs.gpk),
    frost_r: pointHex(inputs.frostR),
    frost_z: inputs.frostZ.toString(),
    old_note: marshalNote("withdraw_multisig", inputs.oldNote),
    old_note_index: inputs.oldNoteIndex.toString(),
    old_note_path: inputs.oldNotePath.map((p) => p.toString()),
    change_note: marshalNote("withdraw_multisig", inputs.changeNote),
    change_eph: inputs.changeEph.toString(),
  });
}
