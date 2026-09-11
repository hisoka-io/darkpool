import { standardWitnessDtoToNoirInput } from "@hisoka/howl-protocol/proving";
import { toStandardWitnessDto } from "@hisoka/wallets/tx";
import { generateProof } from "../../prover-base.js";
import { circuit } from "../../generated/join_circuit.js";
import { JoinInputs, ProofData } from "../../types.js";

export async function proveJoin(inputs: JoinInputs): Promise<ProofData> {
  const dto = toStandardWitnessDto("join", inputs);
  return generateProof(
    "join",
    circuit,
    standardWitnessDtoToNoirInput("join", dto),
  );
}
