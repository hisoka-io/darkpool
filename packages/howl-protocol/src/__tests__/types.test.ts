import { describe, expect, it } from "vitest";

import type { ProofEnvelope } from "../index.js";
import type {
  DepositWitnessDto,
  StandardWitnessByCircuit,
  TransferWitnessDto,
  WithdrawWitnessDto,
} from "../proving/index.js";

function assertCircuitMapping(
  deposit: DepositWitnessDto,
  withdraw: WithdrawWitnessDto,
): void {
  const mapped: StandardWitnessByCircuit["deposit"] = deposit;
  void mapped;

  // @ts-expect-error Withdraw witnesses cannot satisfy the deposit mapping.
  const wrong: StandardWitnessByCircuit["deposit"] = withdraw;
  void wrong;
}
void assertCircuitMapping;

function assertDeepReadonly(witness: TransferWitnessDto): void {
  // @ts-expect-error Nested note fields are readonly.
  witness.old_note.owner = witness.memo_note.owner;
  // @ts-expect-error Merkle path entries are readonly.
  witness.old_note_path[0] = witness.memo_note.owner;
  // @ts-expect-error Nested point coordinates are readonly.
  witness.recipient_spend_pub.x = witness.recipient_view_pub.x;
}
void assertDeepReadonly;

function assertProofEnvelopeShape(envelope: ProofEnvelope<"deposit">): void {
  // @ts-expect-error Proof envelopes never carry a verification claim.
  void envelope.verified;
  // @ts-expect-error Public inputs are readonly and ordered.
  envelope.public_inputs[0] = envelope.public_inputs[1];
}
void assertProofEnvelopeShape;

describe("protocol proving types", () => {
  it("keeps compile-time assertions in the package program", () => {
    expect(true).toBe(true);
  });
});
