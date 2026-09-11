export type ProtocolParseErrorCode =
  | "INVALID_FIELD_HEX"
  | "INVALID_ADDRESS_HEX"
  | "INVALID_BYTES_HEX"
  | "INVALID_UINT_DECIMAL"
  | "UINT_OUT_OF_RANGE"
  | "INVALID_OPERATION_ID"
  | "INVALID_OBJECT"
  | "UNEXPECTED_PROPERTY"
  | "INVALID_CIRCUIT_ID"
  | "INVALID_MERKLE_PATH";

export class ProtocolParseError extends Error {
  constructor(
    readonly code: ProtocolParseErrorCode,
    readonly path: string,
    message: string,
  ) {
    super(`${path}: ${message}`);
    this.name = "ProtocolParseError";
  }
}
