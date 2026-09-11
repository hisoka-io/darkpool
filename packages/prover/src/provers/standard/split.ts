import { standardWitnessDtoToNoirInput } from "@hisoka/howl-protocol/proving";
import { toStandardWitnessDto } from "@hisoka/wallets/tx";
import { generateProof } from "../../prover-base.js";
import { circuit } from "../../generated/split_circuit.js";
import { SplitInputs, ProofData } from "../../types.js";

export async function proveSplit(inputs: SplitInputs): Promise<ProofData> {
  const dto = toStandardWitnessDto("split", inputs);
  return generateProof(
    "split",
    circuit,
    standardWitnessDtoToNoirInput("split", dto),
  );
}
