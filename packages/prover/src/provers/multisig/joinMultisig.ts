import { Fr } from "@aztec/foundation/fields";
import { Point } from "@zk-kit/baby-jubjub";
import { generateProof } from "../../prover-base.js";
import { circuit } from "../../generated/join_multisig_circuit.js";
import { NoteInput, ProofData } from "../../types.js";
import { marshalNote, pointHex } from "../../marshal.js";

export interface JoinMultisigInputs {
  compliancePk: Point<bigint>;

  gpkA: Point<bigint>;
  frostRA: Point<bigint>;
  frostZA: Fr;
  noteA: NoteInput;
  indexA: number;
  pathA: Fr[];

  gpkB: Point<bigint>;
  frostRB: Point<bigint>;
  frostZB: Fr;
  noteB: NoteInput;
  indexB: number;
  pathB: Fr[];

  noteOut: NoteInput;
  ephOut: Fr;
}

export async function proveJoinMultisig(
  inputs: JoinMultisigInputs,
): Promise<ProofData> {
  const c = pointHex(inputs.compliancePk);
  return generateProof("join_multisig", circuit, {
    compliance_pubkey_x: c.x,
    compliance_pubkey_y: c.y,
    gpk_a: pointHex(inputs.gpkA),
    frost_r_a: pointHex(inputs.frostRA),
    frost_z_a: inputs.frostZA.toString(),
    note_a: marshalNote("join_multisig", inputs.noteA),
    index_a: inputs.indexA.toString(),
    path_a: inputs.pathA.map((p) => p.toString()),
    gpk_b: pointHex(inputs.gpkB),
    frost_r_b: pointHex(inputs.frostRB),
    frost_z_b: inputs.frostZB.toString(),
    note_b: marshalNote("join_multisig", inputs.noteB),
    index_b: inputs.indexB.toString(),
    path_b: inputs.pathB.map((p) => p.toString()),
    note_out: marshalNote("join_multisig", inputs.noteOut),
    eph_out: inputs.ephOut.toString(),
  });
}
