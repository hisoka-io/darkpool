import { Fr } from "@aztec/foundation/fields";
import { Point } from "@zk-kit/baby-jubjub";
import { generateProof } from "../../prover-base.js";
import { circuit } from "../../generated/split_multisig_circuit.js";
import { NoteInput, ProofData } from "../../types.js";
import { marshalNote, pointHex } from "../../marshal.js";

export interface SplitMultisigInputs {
  compliancePk: Point<bigint>;

  gpk: Point<bigint>;
  frostR: Point<bigint>;
  frostZ: Fr;

  noteIn: NoteInput;
  indexIn: number;
  pathIn: Fr[];

  noteOut1: NoteInput;
  eph1: Fr;

  noteOut2: NoteInput;
  eph2: Fr;
}

export async function proveSplitMultisig(
  inputs: SplitMultisigInputs,
): Promise<ProofData> {
  const c = pointHex(inputs.compliancePk);
  return generateProof("split_multisig", circuit, {
    compliance_pubkey_x: c.x,
    compliance_pubkey_y: c.y,
    gpk: pointHex(inputs.gpk),
    frost_r: pointHex(inputs.frostR),
    frost_z: inputs.frostZ.toString(),
    note_in: marshalNote("split_multisig", inputs.noteIn),
    index_in: inputs.indexIn.toString(),
    path_in: inputs.pathIn.map((p) => p.toString()),
    note_out_1: marshalNote("split_multisig", inputs.noteOut1),
    eph_1: inputs.eph1.toString(),
    note_out_2: marshalNote("split_multisig", inputs.noteOut2),
    eph_2: inputs.eph2.toString(),
  });
}
