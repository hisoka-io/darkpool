import { Fr } from "@aztec/foundation/fields";

export class PaddingError extends Error {
  constructor(message: string) {
    super(`AES Padding Error: ${message}`);
    this.name = "PaddingError";
  }
}

export class SizeError extends Error {
  constructor(expected: number, actual: number, type: string) {
    super(`Invalid ${type} size: expected ${expected}, got ${actual}`);
    this.name = "SizeError";
  }
}

// Unified Note Structure
export interface NotePlaintext {
  asset_id: Fr;
  value: Fr;
  secret: Fr;
  nullifier: Fr;
  timelock: Fr;
  hashlock: Fr;
}
