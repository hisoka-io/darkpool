import { describe, expect, it } from "vitest";

import {
  BN254_FR_MODULUS,
  ProtocolParseError,
  fieldHexFromBigInt,
  parseAddressHex,
  parseBytesHex,
  parseFieldHex,
  parseOperationId,
  parseUint128Decimal,
  parseUint32Decimal,
  parseUint64Decimal,
  parseUintDecimal,
} from "../index.js";

const FIELD_ZERO = `0x${"00".repeat(32)}`;
const FIELD_ONE = `0x${"00".repeat(31)}01`;
const FIELD_MODULUS_MINUS_ONE =
  "0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000";
const FIELD_MODULUS =
  "0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001";
const FIELD_MODULUS_BIGINT = BigInt(FIELD_MODULUS);

describe("parseFieldHex", () => {
  it.each([FIELD_ZERO, FIELD_ONE, FIELD_MODULUS_MINUS_ONE])(
    "accepts canonical field %s",
    (value: string) => {
      expect(parseFieldHex(value)).toBe(value);
    },
  );

  it.each([
    FIELD_MODULUS,
    `0x${"ff".repeat(32)}`,
    `0X${"00".repeat(32)}`,
    `0x${"AA".repeat(32)}`,
    "0x01",
    `0x${"00".repeat(33)}`,
    ` 0x${"00".repeat(32)}`,
    `${FIELD_ZERO} `,
    "",
    0n,
    null,
  ])("rejects non-canonical field %#", (value: unknown) => {
    expect(() => parseFieldHex(value)).toThrow(ProtocolParseError);
  });

  it("returns the closed field error", () => {
    expect(BN254_FR_MODULUS).toBe(FIELD_MODULUS);
    expect(() => parseFieldHex(FIELD_MODULUS)).toThrowError(
      expect.objectContaining({ code: "INVALID_FIELD_HEX", path: "$" }),
    );
  });
});

describe("fieldHexFromBigInt", () => {
  it.each([
    [0n, FIELD_ZERO],
    [1n, FIELD_ONE],
    [FIELD_MODULUS_BIGINT - 1n, FIELD_MODULUS_MINUS_ONE],
  ])("formats %s as a 32-byte field", (value: bigint, expected: string) => {
    expect(fieldHexFromBigInt(value)).toBe(expected);
  });

  it.each([-1n, FIELD_MODULUS_BIGINT])(
    "rejects out-of-field bigint %s",
    (value: bigint) => {
      expect(() => fieldHexFromBigInt(value)).toThrowError(
        expect.objectContaining({ code: "INVALID_FIELD_HEX", path: "$" }),
      );
    },
  );
});

describe("hex parsers", () => {
  it.each(["0x", "0x00", "0x0123456789abcdef"])(
    "accepts canonical bytes %s",
    (value: string) => {
      expect(parseBytesHex(value)).toBe(value);
    },
  );

  it.each(["", "0X00", "0x0", "0xAA", "0xgg", " 0x00", "0x00 "])(
    "rejects non-canonical bytes %s",
    (value: string) => {
      expect(() => parseBytesHex(value)).toThrowError(
        expect.objectContaining({ code: "INVALID_BYTES_HEX", path: "$" }),
      );
    },
  );

  it("accepts exactly 20 lowercase address bytes", () => {
    const address = `0x${"ab".repeat(20)}`;
    expect(parseAddressHex(address)).toBe(address);
  });

  it.each([
    `0x${"ab".repeat(19)}`,
    `0x${"ab".repeat(21)}`,
    `0X${"ab".repeat(20)}`,
    `0x${"AB".repeat(20)}`,
  ])("rejects non-canonical address %s", (value: string) => {
    expect(() => parseAddressHex(value)).toThrowError(
      expect.objectContaining({ code: "INVALID_ADDRESS_HEX", path: "$" }),
    );
  });

  it("accepts exactly 32 lowercase operation-id bytes", () => {
    const operationId = `0x${"cd".repeat(32)}`;
    expect(parseOperationId(operationId)).toBe(operationId);
  });

  it.each([
    `0x${"cd".repeat(31)}`,
    `0x${"cd".repeat(33)}`,
    `0X${"cd".repeat(32)}`,
    `0x${"CD".repeat(32)}`,
  ])("rejects non-canonical operation id %s", (value: string) => {
    expect(() => parseOperationId(value)).toThrowError(
      expect.objectContaining({ code: "INVALID_OPERATION_ID", path: "$" }),
    );
  });
});

describe("decimal parsers", () => {
  it.each(["0", "1", "10", "43114"])(
    "accepts canonical unsigned decimal %s",
    (value: string) => {
      expect(parseUintDecimal(value)).toBe(value);
    },
  );

  it.each(["", "+1", "-1", "01", "1.0", " 1", "1 ", "1e3", 1, 1n])(
    "rejects non-canonical unsigned decimal %#",
    (value: unknown) => {
      expect(() => parseUintDecimal(value)).toThrowError(
        expect.objectContaining({ code: "INVALID_UINT_DECIMAL", path: "$" }),
      );
    },
  );

  it.each([
    [parseUint32Decimal, "4294967295", true],
    [parseUint32Decimal, "4294967296", false],
    [parseUint64Decimal, "18446744073709551615", true],
    [parseUint64Decimal, "18446744073709551616", false],
    [parseUint128Decimal, "340282366920938463463374607431768211455", true],
    [parseUint128Decimal, "340282366920938463463374607431768211456", false],
  ])(
    "pins integer boundary %s",
    (parse: (value: unknown) => string, value: string, valid: boolean) => {
      if (valid) {
        expect(parse(value)).toBe(value);
        return;
      }

      expect(() => parse(value)).toThrowError(
        expect.objectContaining({ code: "UINT_OUT_OF_RANGE", path: "$" }),
      );
    },
  );
});
