import {
  BN254_FR_MODULUS,
  parseFieldHex,
  parseProofEnvelope,
  type FieldHex,
  type ProofEnvelope,
} from "@hisoka/howl-protocol";
import {
  CIRCUIT_IDS,
  parseCircuitId,
  parseStandardWitnessDto,
  standardWitnessDtoToNoirInput,
  type CircuitId,
  type DepositWitnessDto,
} from "@hisoka/howl-protocol/proving";

const field: FieldHex = parseFieldHex(`0x${"00".repeat(32)}`);
const modulus: string = BN254_FR_MODULUS;
const circuit: CircuitId = parseCircuitId(CIRCUIT_IDS[0]);
declare const rawWitness: unknown;
const witness: DepositWitnessDto = parseStandardWitnessDto(
  "deposit",
  rawWitness,
);
const noirInput = standardWitnessDtoToNoirInput("deposit", witness);
declare const rawEnvelope: unknown;
const envelope: ProofEnvelope<"deposit"> = parseProofEnvelope(
  "deposit",
  rawEnvelope,
);

void field;
void modulus;
void circuit;
void noirInput;
void envelope;
