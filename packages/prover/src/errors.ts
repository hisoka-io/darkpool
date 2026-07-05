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
