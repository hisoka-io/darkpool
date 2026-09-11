import { ProtocolParseError, type ProtocolParseErrorCode } from "./errors.js";

declare const FIELD_HEX_BRAND: unique symbol;
declare const ADDRESS_HEX_BRAND: unique symbol;
declare const BYTES_HEX_BRAND: unique symbol;
declare const UINT_DECIMAL_BRAND: unique symbol;
declare const UINT32_DECIMAL_BRAND: unique symbol;
declare const UINT64_DECIMAL_BRAND: unique symbol;
declare const UINT128_DECIMAL_BRAND: unique symbol;
declare const OPERATION_ID_BRAND: unique symbol;

export type FieldHex = string & { readonly [FIELD_HEX_BRAND]: true };
export type AddressHex = string & { readonly [ADDRESS_HEX_BRAND]: true };
export type BytesHex = string & { readonly [BYTES_HEX_BRAND]: true };
export type UintDecimal = string & { readonly [UINT_DECIMAL_BRAND]: true };
export type Uint32Decimal = UintDecimal & {
  readonly [UINT32_DECIMAL_BRAND]: true;
};
export type Uint64Decimal = UintDecimal & {
  readonly [UINT64_DECIMAL_BRAND]: true;
};
export type Uint128Decimal = UintDecimal & {
  readonly [UINT128_DECIMAL_BRAND]: true;
};
export type OperationId = string & { readonly [OPERATION_ID_BRAND]: true };

const FIELD_HEX_PATTERN = /^0x[0-9a-f]{64}$/;
const ADDRESS_HEX_PATTERN = /^0x[0-9a-f]{40}$/;
const BYTES_HEX_PATTERN = /^0x(?:[0-9a-f]{2})*$/;
const UINT_DECIMAL_PATTERN = /^(?:0|[1-9][0-9]*)$/;
const OPERATION_ID_PATTERN = /^0x[0-9a-f]{64}$/;

const UINT32_MAX_DECIMAL = "4294967295";
const UINT64_MAX_DECIMAL = "18446744073709551615";
const UINT128_MAX_DECIMAL = "340282366920938463463374607431768211455";

// @aztec/foundation@2.1.11 src/fields/fields.ts, Fr.MODULUS.
export const BN254_FR_MODULUS =
  "0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001" as const;

const BN254_FR_MODULUS_BIGINT = BigInt(BN254_FR_MODULUS);

function parseBrandedString<T extends string>(
  value: unknown,
  pattern: RegExp,
  code: ProtocolParseErrorCode,
  path: string,
  expectation: string,
): T {
  if (typeof value !== "string" || !pattern.test(value)) {
    throw new ProtocolParseError(code, path, expectation);
  }

  return value as T;
}

export function parseFieldHexAtPath(value: unknown, path: string): FieldHex {
  const field = parseBrandedString<FieldHex>(
    value,
    FIELD_HEX_PATTERN,
    "INVALID_FIELD_HEX",
    path,
    "expected lowercase 0x-prefixed 32-byte field below the BN254 Fr modulus",
  );
  if (BigInt(field) >= BN254_FR_MODULUS_BIGINT) {
    throw new ProtocolParseError(
      "INVALID_FIELD_HEX",
      path,
      "field value must be below the BN254 Fr modulus",
    );
  }

  return field;
}

export function parseFieldHex(value: unknown): FieldHex {
  return parseFieldHexAtPath(value, "$");
}

export function fieldHexFromBigInt(value: bigint): FieldHex {
  if (
    typeof value !== "bigint" ||
    value < 0n ||
    value >= BN254_FR_MODULUS_BIGINT
  ) {
    throw new ProtocolParseError(
      "INVALID_FIELD_HEX",
      "$",
      "bigint field value must be non-negative and below the BN254 Fr modulus",
    );
  }

  return `0x${value.toString(16).padStart(64, "0")}` as FieldHex;
}

export function parseAddressHexAtPath(
  value: unknown,
  path: string,
): AddressHex {
  return parseBrandedString<AddressHex>(
    value,
    ADDRESS_HEX_PATTERN,
    "INVALID_ADDRESS_HEX",
    path,
    "expected lowercase 0x-prefixed 20-byte address",
  );
}

export function parseAddressHex(value: unknown): AddressHex {
  return parseAddressHexAtPath(value, "$");
}

export function parseBytesHex(value: unknown): BytesHex {
  return parseBrandedString<BytesHex>(
    value,
    BYTES_HEX_PATTERN,
    "INVALID_BYTES_HEX",
    "$",
    "expected lowercase 0x-prefixed even-length bytes",
  );
}

export function parseOperationId(value: unknown): OperationId {
  return parseBrandedString<OperationId>(
    value,
    OPERATION_ID_PATTERN,
    "INVALID_OPERATION_ID",
    "$",
    "expected lowercase 0x-prefixed 32-byte operation id",
  );
}

export function parseUintDecimalAtPath(
  value: unknown,
  path: string,
): UintDecimal {
  return parseBrandedString<UintDecimal>(
    value,
    UINT_DECIMAL_PATTERN,
    "INVALID_UINT_DECIMAL",
    path,
    "expected canonical unsigned decimal string",
  );
}

export function parseUintDecimal(value: unknown): UintDecimal {
  return parseUintDecimalAtPath(value, "$");
}

function parseBoundedUint<T extends UintDecimal>(
  value: unknown,
  maximum: string,
  path: string,
): T {
  const decimal = parseUintDecimalAtPath(value, path);
  if (
    decimal.length > maximum.length ||
    (decimal.length === maximum.length && decimal > maximum)
  ) {
    throw new ProtocolParseError(
      "UINT_OUT_OF_RANGE",
      path,
      `unsigned decimal exceeds maximum ${maximum}`,
    );
  }

  return decimal as T;
}

export function parseUint32Decimal(value: unknown): Uint32Decimal {
  return parseBoundedUint<Uint32Decimal>(value, UINT32_MAX_DECIMAL, "$");
}

export function parseUint64Decimal(value: unknown): Uint64Decimal {
  return parseBoundedUint<Uint64Decimal>(value, UINT64_MAX_DECIMAL, "$");
}

export function parseUint128Decimal(value: unknown): Uint128Decimal {
  return parseBoundedUint<Uint128Decimal>(value, UINT128_MAX_DECIMAL, "$");
}
