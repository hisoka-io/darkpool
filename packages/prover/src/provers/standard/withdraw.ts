import { standardWitnessDtoToNoirInput } from "@hisoka/howl-protocol/proving";
import { toStandardWitnessDto } from "@hisoka/wallets/tx";
import { generateProof } from "../../prover-base.js";
import { circuit } from "../../generated/withdraw_circuit.js";
import { WithdrawInputs, ProofData } from "../../types.js";

export async function proveWithdraw(
  inputs: WithdrawInputs,
): Promise<ProofData> {
  const dto = toStandardWitnessDto("withdraw", inputs);
  return generateProof(
    "withdraw",
    circuit,
    standardWitnessDtoToNoirInput("withdraw", dto),
  );
}
