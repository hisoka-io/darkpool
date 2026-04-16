import { generateProof } from "../prover-base.js";
import { circuit } from "../generated/split_circuit.js";
import { SplitInputs, ProofData } from "../types.js";

export async function proveSplit(inputs: SplitInputs): Promise<ProofData> {
  const noirInputs = {
    merkle_root: inputs.merkleRoot.toString(),
    current_timestamp: inputs.currentTimestamp.toString(),
    compliance_pubkey_x: `0x${inputs.compliancePk[0].toString(16)}`,
    compliance_pubkey_y: `0x${inputs.compliancePk[1].toString(16)}`,
    note_in: {
      asset_id: inputs.noteIn.asset_id.toString(),
      value: inputs.noteIn.value.toString(),
      secret: inputs.noteIn.secret.toString(),
      nullifier: inputs.noteIn.nullifier.toString(),
      timelock: inputs.noteIn.timelock.toString(),
      hashlock: inputs.noteIn.hashlock.toString(),
    },
    secret_in: inputs.secretIn.toString(),
    index_in: inputs.indexIn.toString(),
    path_in: inputs.pathIn.map((p) => p.toString()),
    preimage_in: inputs.preimageIn.toString(),
    note_out_1: {
      asset_id: inputs.noteOut1.asset_id.toString(),
      value: inputs.noteOut1.value.toString(),
      secret: inputs.noteOut1.secret.toString(),
      nullifier: inputs.noteOut1.nullifier.toString(),
      timelock: inputs.noteOut1.timelock.toString(),
      hashlock: inputs.noteOut1.hashlock.toString(),
    },
    sk_out_1: inputs.skOut1.toString(),
    note_out_2: {
      asset_id: inputs.noteOut2.asset_id.toString(),
      value: inputs.noteOut2.value.toString(),
      secret: inputs.noteOut2.secret.toString(),
      nullifier: inputs.noteOut2.nullifier.toString(),
      timelock: inputs.noteOut2.timelock.toString(),
      hashlock: inputs.noteOut2.hashlock.toString(),
    },
    sk_out_2: inputs.skOut2.toString(),
  };
  return generateProof(circuit, noirInputs);
}
