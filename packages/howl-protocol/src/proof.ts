import { ProtocolParseError } from "./errors.js";
import {
  parseAtPath,
  readExactArray,
  readExactObject,
} from "./internal/exact-object.js";
import {
  parseCircuitIdAtPath,
  publicInputCountForCircuit,
  type CircuitId,
} from "./internal/circuits.js";
import {
  parseBytesHex,
  parseFieldHexAtPath,
  type BytesHex,
  type FieldHex,
} from "./primitives.js";
const PROOF_ENVELOPE_KEYS = ["circuit_id", "proof", "public_inputs"] as const;

export interface ProofEnvelope<C extends CircuitId = CircuitId> {
  readonly circuit_id: C;
  readonly proof: BytesHex;
  readonly public_inputs: readonly FieldHex[];
}

export function parseProofEnvelope<C extends CircuitId>(
  expectedCircuit: C,
  value: unknown,
): ProofEnvelope<C> {
  parseCircuitIdAtPath(expectedCircuit, "$");
  const envelope = readExactObject(value, PROOF_ENVELOPE_KEYS, "$");
  const envelopeCircuit = parseCircuitIdAtPath(
    envelope.circuit_id,
    "$.circuit_id",
  );
  if (envelopeCircuit !== expectedCircuit) {
    throw new ProtocolParseError(
      "INVALID_CIRCUIT_ID",
      "$.circuit_id",
      `expected circuit id ${expectedCircuit}`,
    );
  }

  const publicInputCount = publicInputCountForCircuit(expectedCircuit);
  const publicInputs = readExactArray(
    envelope.public_inputs,
    "$.public_inputs",
    {
      expectedLength: publicInputCount,
      errorCode: "INVALID_OBJECT",
      errorMessage: `expected exactly ${publicInputCount} public inputs`,
    },
  ).map((field, index) =>
    parseFieldHexAtPath(field, `$.public_inputs[${index}]`),
  );

  return {
    circuit_id: expectedCircuit,
    proof: parseAtPath(parseBytesHex, envelope.proof, "$.proof"),
    public_inputs: publicInputs,
  };
}
