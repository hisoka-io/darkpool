import { standardWitnessDtoToNoirInput } from "@hisoka/howl-protocol/proving";
import { toStandardWitnessDto } from "@hisoka/wallets/tx";
import { generateProof } from "../../prover-base.js";
import { circuit } from "../../generated/transfer_circuit.js";
import { TransferInputs, ProofData } from "../../types.js";

export async function proveTransfer(
  inputs: TransferInputs,
): Promise<ProofData> {
  const dto = toStandardWitnessDto("transfer", inputs);
  return generateProof(
    "transfer",
    circuit,
    standardWitnessDtoToNoirInput("transfer", dto),
  );
}
