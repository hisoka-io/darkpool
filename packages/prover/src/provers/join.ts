import { generateProof } from "../prover-base.js";
import { circuit } from "../generated/join_circuit.js";
import { JoinInputs, ProofData } from "../types.js";

export async function proveJoin(inputs: JoinInputs): Promise<ProofData> {
  const noirInputs = {
    merkle_root: inputs.merkleRoot.toString(),
    current_timestamp: inputs.currentTimestamp.toString(),
    compliance_pubkey_x: `0x${inputs.compliancePk[0].toString(16)}`,
    compliance_pubkey_y: `0x${inputs.compliancePk[1].toString(16)}`,
    note_a: {
      asset_id: inputs.noteA.asset_id.toString(),
      value: inputs.noteA.value.toString(),
      secret: inputs.noteA.secret.toString(),
      nullifier: inputs.noteA.nullifier.toString(),
      timelock: inputs.noteA.timelock.toString(),
      hashlock: inputs.noteA.hashlock.toString(),
    },
    secret_a: inputs.secretA.toString(),
    index_a: inputs.indexA.toString(),
    path_a: inputs.pathA.map((p) => p.toString()),
    preimage_a: inputs.preimageA.toString(),
    note_b: {
      asset_id: inputs.noteB.asset_id.toString(),
      value: inputs.noteB.value.toString(),
      secret: inputs.noteB.secret.toString(),
      nullifier: inputs.noteB.nullifier.toString(),
      timelock: inputs.noteB.timelock.toString(),
      hashlock: inputs.noteB.hashlock.toString(),
    },
    secret_b: inputs.secretB.toString(),
    index_b: inputs.indexB.toString(),
    path_b: inputs.pathB.map((p) => p.toString()),
    preimage_b: inputs.preimageB.toString(),
    note_out: {
      asset_id: inputs.noteOut.asset_id.toString(),
      value: inputs.noteOut.value.toString(),
      secret: inputs.noteOut.secret.toString(),
      nullifier: inputs.noteOut.nullifier.toString(),
      timelock: inputs.noteOut.timelock.toString(),
      hashlock: inputs.noteOut.hashlock.toString(),
    },
    sk_out: inputs.skOut.toString(),
  };
  return generateProof(circuit, noirInputs);
}
