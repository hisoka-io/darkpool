import { standardWitnessDtoToNoirInput } from "@hisoka/howl-protocol/proving";
import { toStandardWitnessDto } from "@hisoka/wallets/tx";
import { generateProof } from "../../prover-base.js";
import { circuit } from "../../generated/public_claim_circuit.js";
import { PublicClaimInputs, ProofData } from "../../types.js";

export async function provePublicClaim(
  inputs: PublicClaimInputs,
): Promise<ProofData> {
  const dto = toStandardWitnessDto("public_claim", inputs);
  return generateProof(
    "public_claim",
    circuit,
    standardWitnessDtoToNoirInput("public_claim", dto),
  );
}
