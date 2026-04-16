import { generateProof } from "../prover-base.js";
import { circuit } from "../generated/deposit_circuit.js";
import { DepositInputs, ProofData } from "../types.js";

export async function proveDeposit(inputs: DepositInputs): Promise<ProofData> {
  const noirInputs = {
    compliance_pubkey_x: `0x${inputs.compliancePk[0].toString(16)}`,
    compliance_pubkey_y: `0x${inputs.compliancePk[1].toString(16)}`,
    ephemeral_sk: inputs.ephemeralSk.toString(),
    note_plaintext: {
      asset_id: inputs.notePlaintext.asset_id.toString(),
      value: inputs.notePlaintext.value.toString(),
      secret: inputs.notePlaintext.secret.toString(),
      nullifier: inputs.notePlaintext.nullifier.toString(),
      timelock: inputs.notePlaintext.timelock.toString(),
      hashlock: inputs.notePlaintext.hashlock.toString(),
    },
  };
  return generateProof(circuit, noirInputs);
}
