export class ProofError extends Error {
  constructor(
    public readonly circuit: string,
    message: string,
    public readonly cause?: unknown,
  ) {
    super(`proof failed for ${circuit}: ${message}`);
    this.name = "ProofError";
  }
}

export class ProofInputError extends Error {
  constructor(
    public readonly circuit: string,
    message: string,
  ) {
    super(`invalid input for ${circuit}: ${message}`);
    this.name = "ProofInputError";
  }
}

/** The proof was generated but failed local verification; submitting it would only revert on chain. */
export class UnverifiedProofError extends ProofError {
  constructor(circuit: string) {
    super(
      circuit,
      "the generated proof does not verify against this circuit's verification key, so it was not returned",
    );
    this.name = "UnverifiedProofError";
  }
}
