import { describe, expect, it } from "vitest";
import {
  COLLECTIONS,
  Collection,
  PssProtocolError,
  assertCount,
  bytesEqual,
  decodeAccountIdPath,
  decodeCollectionPath,
  deletePreimage,
  encodeAccountIdPath,
  fromBase64,
  fromHex,
  isCollection,
  parseDeleteAccountRequest,
  parsePutBlobRequest,
  putPreimage,
  toBase64,
  toHex,
  u64be,
} from "../wire/index.js";

function bytes(...values: number[]): Uint8Array {
  return Uint8Array.from(values);
}

function filled(length: number, value: number): Uint8Array {
  return new Uint8Array(length).fill(value);
}

const ACCOUNT_ID = filled(32, 0xa1);
const DIGEST = filled(32, 0xb2);
const NONCE = filled(12, 0xc3);

describe("base64 codec", () => {
  it("round trips every length up to 3 full groups", () => {
    for (let length = 0; length <= 12; length++) {
      const input = Uint8Array.from({ length }, (_, i) => (i * 37) % 256);
      expect(fromBase64(toBase64(input), "probe")).toEqual(input);
    }
  });

  it("emits the RFC 4648 examples", () => {
    expect(toBase64(new TextEncoder().encode("f"))).toBe("Zg==");
    expect(toBase64(new TextEncoder().encode("fo"))).toBe("Zm8=");
    expect(toBase64(new TextEncoder().encode("foo"))).toBe("Zm9v");
    expect(toBase64(new TextEncoder().encode("foobar"))).toBe("Zm9vYmFy");
  });

  it("rejects a non-canonical spelling of the same bytes", () => {
    expect(fromBase64("Zg==", "probe")).toEqual(new TextEncoder().encode("f"));
    // "Zh==" decodes to the same single byte under a lax decoder because the trailing bits are ignored.
    expect(() => fromBase64("Zh==", "probe")).toThrow(PssProtocolError);
  });

  it("rejects wrong length, stray padding and non-alphabet characters", () => {
    for (const bad of ["Zg=", "Z", "Zg=a", "Zm9v!", "Zm 9v", "Zg==="]) {
      expect(() => fromBase64(bad, "probe")).toThrow(PssProtocolError);
    }
  });
});

describe("hex codec", () => {
  it("round trips", () => {
    const input = bytes(0, 1, 15, 16, 254, 255);
    expect(toHex(input)).toBe("0x00010f10feff");
    expect(fromHex(toHex(input), "probe")).toEqual(input);
  });

  it("rejects uppercase and a missing prefix", () => {
    expect(() => fromHex("0xAB", "probe")).toThrow(PssProtocolError);
    expect(() => fromHex("ab", "probe")).toThrow(PssProtocolError);
  });
});

describe("integer encoding", () => {
  it("encodes big-endian u64", () => {
    expect(u64be(0, "n")).toEqual(filled(8, 0));
    expect(u64be(1, "n")).toEqual(bytes(0, 0, 0, 0, 0, 0, 0, 1));
    expect(u64be(256, "n")).toEqual(bytes(0, 0, 0, 0, 0, 0, 1, 0));
    expect(u64be(Number.MAX_SAFE_INTEGER, "n")).toEqual(
      bytes(0, 0x1f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff),
    );
  });

  it("refuses values that cannot survive a JSON round trip", () => {
    for (const bad of [
      -1,
      1.5,
      Number.NaN,
      Number.POSITIVE_INFINITY,
      2 ** 53,
    ]) {
      expect(() => assertCount(bad, "n")).toThrow(PssProtocolError);
    }
    expect(() => assertCount("7", "n")).toThrow(PssProtocolError);
  });
});

describe("collections", () => {
  it("recognises exactly state and labels", () => {
    expect(COLLECTIONS).toEqual(["state", "labels"]);
    expect(isCollection("state")).toBe(true);
    expect(isCollection("labels")).toBe(true);
    expect(isCollection("secrets")).toBe(false);
    expect(() => decodeCollectionPath("secrets")).toThrow(PssProtocolError);
  });
});

describe("account id path", () => {
  it("round trips as unprefixed lowercase hex", () => {
    const path = encodeAccountIdPath(ACCOUNT_ID);
    expect(path).toHaveLength(64);
    expect(path).toMatch(/^[0-9a-f]{64}$/);
    expect(decodeAccountIdPath(path)).toEqual(ACCOUNT_ID);
  });

  it("rejects a wrong-length account id", () => {
    expect(() => decodeAccountIdPath("ab")).toThrow(PssProtocolError);
    expect(() => encodeAccountIdPath(filled(31, 1))).toThrow(PssProtocolError);
  });
});

describe("signing preimage", () => {
  const base = {
    accountId: ACCOUNT_ID,
    collection: "state" as Collection,
    version: 7,
    prevVersion: 6,
    ciphertextDigest: DIGEST,
    timestamp: 1_785_900_000,
  };

  it("has the expected fixed length for a known collection", () => {
    // 10 prefix + 32 accountId + 1 length + 5 "state" + 8 version + 8 prevVersion + 32 digest + 8 timestamp
    expect(putPreimage(base)).toHaveLength(104);
    expect(putPreimage({ ...base, collection: "labels" })).toHaveLength(105);
  });

  it("separates the two collections at the same version", () => {
    const asState = putPreimage(base);
    const asLabels = putPreimage({ ...base, collection: "labels" });
    expect(bytesEqual(asState, asLabels)).toBe(false);
  });

  it("is injective across every field", () => {
    const variants = [
      base,
      { ...base, collection: "labels" as Collection },
      { ...base, version: 8 },
      { ...base, prevVersion: 5 },
      { ...base, timestamp: base.timestamp + 1 },
      { ...base, accountId: filled(32, 0xa2) },
      { ...base, ciphertextDigest: filled(32, 0xb3) },
      // The pair that a decimal-ASCII concatenation would collapse: "7"+"6" and "76"+"" both read as 76.
      { ...base, version: 76, prevVersion: 0 },
      { ...base, version: 7, prevVersion: 60 },
    ];
    const seen = new Set(variants.map((v) => toHex(putPreimage(v))));
    expect(seen.size).toBe(variants.length);
  });

  it("binds the accountId and digest lengths", () => {
    expect(() => putPreimage({ ...base, accountId: filled(31, 1) })).toThrow(
      PssProtocolError,
    );
    expect(() =>
      putPreimage({ ...base, ciphertextDigest: filled(31, 1) }),
    ).toThrow(PssProtocolError);
  });

  it("separates a delete from a put", () => {
    const del = deletePreimage({
      accountId: ACCOUNT_ID,
      nonce: NONCE,
      timestamp: base.timestamp,
    });
    expect(del).toHaveLength(62);
    expect(bytesEqual(del, putPreimage(base))).toBe(false);
  });

  it("is injective across delete fields", () => {
    const del = (nonce: Uint8Array, timestamp: number): string =>
      toHex(deletePreimage({ accountId: ACCOUNT_ID, nonce, timestamp }));
    expect(del(NONCE, 1)).not.toBe(del(filled(12, 0xc4), 1));
    expect(del(NONCE, 1)).not.toBe(del(NONCE, 2));
  });
});

describe("request parsing", () => {
  const put = {
    version: 2,
    prevVersion: 1,
    nonce: toBase64(NONCE),
    ciphertext: toBase64(filled(64, 9)),
    authPk: toBase64(filled(32, 3)),
    sig: toBase64(filled(64, 4)),
    timestamp: 1_785_900_000,
  };

  it("accepts a well formed put and decodes its binary fields", () => {
    const parsed = parsePutBlobRequest(put);
    expect(parsed.nonce).toEqual(NONCE);
    expect(parsed.ciphertext).toHaveLength(64);
    expect(parsed.invite).toBeNull();
  });

  it("accepts an invite code", () => {
    expect(parsePutBlobRequest({ ...put, invite: "abc-123_XYZ" }).invite).toBe(
      "abc-123_XYZ",
    );
  });

  it("rejects a malformed field rather than coercing it", () => {
    const bad: Record<string, unknown>[] = [
      { ...put, version: -1 },
      { ...put, version: "2" },
      { ...put, prevVersion: 1.5 },
      { ...put, nonce: toBase64(filled(11, 0)) },
      { ...put, authPk: toBase64(filled(31, 0)) },
      { ...put, sig: toBase64(filled(63, 0)) },
      { ...put, ciphertext: toBase64(new Uint8Array(0)) },
      { ...put, timestamp: Number.NaN },
      { ...put, invite: "not a code!" },
    ];
    for (const body of bad) {
      expect(() => parsePutBlobRequest(body)).toThrow(PssProtocolError);
    }
    expect(() => parsePutBlobRequest(null)).toThrow(PssProtocolError);
    expect(() => parsePutBlobRequest([])).toThrow(PssProtocolError);
  });

  it("parses a delete and requires a 12 byte nonce", () => {
    const del = {
      authPk: toBase64(filled(32, 3)),
      sig: toBase64(filled(64, 4)),
      timestamp: 1_785_900_000,
      nonce: toBase64(NONCE),
    };
    expect(parseDeleteAccountRequest(del).nonce).toEqual(NONCE);
    expect(() =>
      parseDeleteAccountRequest({ ...del, nonce: toBase64(filled(16, 0)) }),
    ).toThrow(PssProtocolError);
  });
});

describe("constant time comparison", () => {
  it("compares by content and length", () => {
    expect(bytesEqual(bytes(1, 2, 3), bytes(1, 2, 3))).toBe(true);
    expect(bytesEqual(bytes(1, 2, 3), bytes(1, 2, 4))).toBe(false);
    expect(bytesEqual(bytes(1, 2, 3), bytes(1, 2))).toBe(false);
  });
});
