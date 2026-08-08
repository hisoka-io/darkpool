import { describe, expect, it } from "vitest";
import {
  BODY_HEADROOM_BYTES,
  MAX_CIPHERTEXT_BYTES,
  toBase64,
} from "@hisoka/pss-client/wire";
import {
  MAX_DELETE_BODY_BYTES,
  base64Bytes,
  base64Chars,
  maxPutBodyBytes,
} from "../http/limits.js";

describe("base64 sizing", () => {
  it("matches the encoder at every remainder", () => {
    for (let length = 0; length <= 12; length++) {
      const encoded = toBase64(new Uint8Array(length));
      expect(base64Chars(length)).toBe(encoded.length);
      expect(base64Bytes(encoded)).toBe(length);
    }
  });

  it("reads the decoded size of a maximum ciphertext and of one byte more", () => {
    expect(base64Bytes(toBase64(new Uint8Array(MAX_CIPHERTEXT_BYTES)))).toBe(
      MAX_CIPHERTEXT_BYTES,
    );
    expect(
      base64Bytes(toBase64(new Uint8Array(MAX_CIPHERTEXT_BYTES + 1))),
    ).toBe(MAX_CIPHERTEXT_BYTES + 1);
  });

  it("declines to size a string that cannot be base64", () => {
    expect(base64Bytes("abc")).toBeNull();
    expect(base64Bytes("a")).toBeNull();
  });
});

const putCap = (): number =>
  maxPutBodyBytes(MAX_CIPHERTEXT_BYTES, BODY_HEADROOM_BYTES);

function widestPut(): string {
  return JSON.stringify({
    version: Number.MAX_SAFE_INTEGER,
    prevVersion: Number.MAX_SAFE_INTEGER,
    timestamp: Number.MAX_SAFE_INTEGER,
    nonce: toBase64(new Uint8Array(12)),
    ciphertext: toBase64(new Uint8Array(MAX_CIPHERTEXT_BYTES)),
    authPk: toBase64(new Uint8Array(32)),
    sig: toBase64(new Uint8Array(64)),
    invite: "i".repeat(128),
  });
}

describe("body caps", () => {
  it("admits the widest legal put and nothing beyond it", () => {
    const widest = widestPut();
    expect(widest.length).toBeLessThanOrEqual(putCap());
    // Without this the test passes even if the cap is gutted to MAX_SAFE_INTEGER.
    expect(putCap()).toBeLessThan(widest.length + MAX_CIPHERTEXT_BYTES);
  });

  // The create path is where this bites: the invite allowance is spare only while no invite is sent, so
  // a maximal create was previously exactly on the cap and any inserted whitespace was a 413 on signup.
  it("admits a pretty-printed maximal create", () => {
    const widest = widestPut();
    for (const indent of [2, 4]) {
      const pretty = JSON.stringify(JSON.parse(widest), null, indent);
      expect(pretty.length).toBeGreaterThan(widest.length);
      expect(pretty.length).toBeLessThanOrEqual(putCap());
    }
  });

  it("keeps the headroom bounded rather than open ended", () => {
    expect(putCap() - widestPut().length).toBe(BODY_HEADROOM_BYTES);
  });

  it("admits the widest legal delete and nothing beyond it", () => {
    const widest = JSON.stringify({
      timestamp: Number.MAX_SAFE_INTEGER,
      nonce: toBase64(new Uint8Array(12)),
      authPk: toBase64(new Uint8Array(32)),
      sig: toBase64(new Uint8Array(64)),
    });
    expect(widest.length).toBeLessThanOrEqual(MAX_DELETE_BODY_BYTES);
    expect(MAX_DELETE_BODY_BYTES).toBeLessThan(putCap());
    // The cap carries whitespace headroom, not an open end.
    expect(MAX_DELETE_BODY_BYTES).toBeLessThan(widest.length * 4);
    // A pretty-printed but otherwise identical body is still legal and must fit.
    const pretty = JSON.stringify(JSON.parse(widest), null, 2);
    expect(pretty.length).toBeGreaterThan(widest.length);
    expect(pretty.length).toBeLessThanOrEqual(MAX_DELETE_BODY_BYTES);
  });
});
