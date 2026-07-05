import { describe, it, expect } from "vitest";
import { Point } from "@zk-kit/baby-jubjub";
import {
  encodeHisokaAddress,
  decodeHisokaAddress,
  HisokaAddress,
} from "../address";

// Transfer-memo in_pub_j (gen_v2_fixtures.ts): an even-y prime-order point usable as a payment address.
const IN_PUB: Point<bigint> = [
  0x1b16e357953d68d73398c838aa883cc65ddae2aef75a4bc437e4232afdbe43c8n,
  0x02d7ee0be055310d2895c5ed5090a8aa1c700e73c64294f1e817ec77f46b4fdcn,
];

describe("Hisoka payment address (in_pub_j + diversifier index)", () => {
  const addr: HisokaAddress = { inPub: IN_PUB, index: 7n };

  it("round-trips encode/decode without loss", () => {
    const decoded = decodeHisokaAddress(encodeHisokaAddress(addr));
    expect(decoded.inPub[0]).toBe(IN_PUB[0]);
    expect(decoded.inPub[1]).toBe(IN_PUB[1]);
    expect(decoded.index).toBe(7n);
  });

  it("uses the hiso_ prefix", () => {
    expect(encodeHisokaAddress(addr).startsWith("hiso_")).toBe(true);
  });

  it("rejects a wrong prefix", () => {
    const tampered = encodeHisokaAddress(addr).replace("hiso_", "invalid_");
    expect(() => decodeHisokaAddress(tampered)).toThrow(/prefix/);
  });

  it("rejects a corrupted checksum", () => {
    const parts = encodeHisokaAddress(addr).split("_");
    const last = parts[1].slice(-1);
    const flipped = last === "A" ? "B" : "A";
    const corrupted = `${parts[0]}_${parts[1].slice(0, -1)}${flipped}`;
    expect(() => decodeHisokaAddress(corrupted)).toThrow(/checksum/i);
  });

  it("rejects an off-curve point on encode", () => {
    expect(() =>
      encodeHisokaAddress({ inPub: [1n, 2n] as Point<bigint>, index: 0n }),
    ).toThrow(/curve/);
  });
});
