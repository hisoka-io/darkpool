import protocol = require("@hisoka/howl-protocol");
import proving = require("@hisoka/howl-protocol/proving");

const field: protocol.FieldHex = protocol.parseFieldHex(`0x${"00".repeat(32)}`);
const modulus: string = protocol.BN254_FR_MODULUS;
const circuit: proving.CircuitId = proving.parseCircuitId(
  proving.CIRCUIT_IDS[0],
);
declare const rawWitness: unknown;
const witness: proving.DepositWitnessDto = proving.parseStandardWitnessDto(
  "deposit",
  rawWitness,
);
const noirInput = proving.standardWitnessDtoToNoirInput("deposit", witness);
declare const rawEnvelope: unknown;
const envelope: protocol.ProofEnvelope<"deposit"> = protocol.parseProofEnvelope(
  "deposit",
  rawEnvelope,
);

void field;
void modulus;
void circuit;
void noirInput;
void envelope;
