import { standardWitnessDtoToNoirInput } from "@hisoka/howl-protocol/proving";
import { toStandardWitnessDto } from "@hisoka/wallets/tx";
import { generateProof } from "../../prover-base.js";
import { circuit } from "../../generated/deposit_circuit.js";
import { DepositInputs, ProofData } from "../../types.js";

export async function proveDeposit(inputs: DepositInputs): Promise<ProofData> {
  const dto = toStandardWitnessDto("deposit", inputs);
  return generateProof(
    "deposit",
    circuit,
    standardWitnessDtoToNoirInput("deposit", dto),
  );
}
