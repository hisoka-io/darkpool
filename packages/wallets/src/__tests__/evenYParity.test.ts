import { describe, it, expect } from "vitest";
import { Base8, mulPointEscalar, packPoint, Point } from "@zk-kit/baby-jubjub";
import bs58check from "bs58check";
import { isEvenY } from "../note/keys";
import { decodeHisokaAddress, encodeHisokaAddress } from "../address";

// BabyJubJub base field == BN254 scalar field. A point's y is the canonical residue in [0, P).
const BN254_P =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

// Noir even_y.nr reads y.to_le_bytes()[0] & 1; byte 0 is the low byte, so its LSB is y & 1.
function noirIsEvenY(y: bigint): boolean {
  const canonical = ((y % BN254_P) + BN254_P) % BN254_P;
  return (canonical & 0xffn & 1n) === 0n;
}

function be32(num: bigint): Buffer {
  return Buffer.from(num.toString(16).padStart(64, "0"), "hex");
}

// The exact points asserted in packages/circuits/shared/src/even_y.nr #[test].
const NOIR_ODD: Point<bigint> = [
  0x1f082615764661f46f203a3d3d4336d5d7273bf17a67d15bd485a7f329f47c93n,
  0x288d616819eb80b160bc2157bdbbd872bfe393957ee45a4aa222587e58a1bb47n,
];
const NOIR_EVEN: Point<bigint> = [
  0x13bf364f3ed4490cd6a62bf0d6be4923b09ca23e761d654c7033321c381ba057n,
  0x2071ecc0c290d14de1059e9e7594170da51ea08c071d2812bb047692e4e91338n,
];
const NOIR_FIXTURE: Point<bigint> = [
  0x158b1d9682257c0832785c20b002c360b7f84f59f253e667659cf90c1455f764n,
  0x132a0f65758b4775374cfc0a98d7f8a186e1cad626e4e4cd37b73532d7e50101n,
];

describe("even-y parity KAT (TS isEvenY == Noir even_y.nr)", () => {
  it("agrees with the even_y.nr #[test] verdicts on its exact points", () => {
    expect(isEvenY(NOIR_ODD)).toBe(false);
    expect(isEvenY(NOIR_EVEN)).toBe(true);
    expect(isEvenY(NOIR_FIXTURE)).toBe(false);

    expect(isEvenY(NOIR_ODD)).toBe(noirIsEvenY(NOIR_ODD[1]));
    expect(isEvenY(NOIR_EVEN)).toBe(noirIsEvenY(NOIR_EVEN[1]));
    expect(isEvenY(NOIR_FIXTURE)).toBe(noirIsEvenY(NOIR_FIXTURE[1]));
  });

  it("matches the byte-0-LSB canonicalization across a y spread including y near P/2", () => {
    const half = BN254_P >> 1n;
    const spread: bigint[] = [
      0n,
      1n,
      2n,
      3n,
      254n,
      255n,
      256n,
      257n,
      half - 1n,
      half,
      half + 1n,
      BN254_P - 2n,
      BN254_P - 1n,
      NOIR_ODD[1],
      NOIR_EVEN[1],
      NOIR_FIXTURE[1],
    ];
    for (const y of spread) {
      const pub: Point<bigint> = [1n, y];
      expect(isEvenY(pub)).toBe(noirIsEvenY(y));
    }
  });
});

describe("odd-y discovery-tag rejection in address encode/decode", () => {
  const ODD_ADDRESS_POINT = mulPointEscalar(Base8, 789n);

  it("the reference odd-y point really is odd-y and on the prime-order subgroup", () => {
    expect(ODD_ADDRESS_POINT[0]).toBe(NOIR_FIXTURE[0]);
    expect(ODD_ADDRESS_POINT[1]).toBe(NOIR_FIXTURE[1]);
    expect(isEvenY(ODD_ADDRESS_POINT)).toBe(false);
  });

  it("rejects an odd-y point on encode", () => {
    expect(() =>
      encodeHisokaAddress({ inPub: ODD_ADDRESS_POINT, index: 0n }),
    ).toThrow(/odd y/i);
  });

  it("rejects a crafted odd-y payload on decode", () => {
    const payload = Buffer.concat([
      be32(packPoint(ODD_ADDRESS_POINT)),
      be32(0n),
    ]);
    const address = `hiso_${bs58check.encode(payload)}`;
    expect(() => decodeHisokaAddress(address)).toThrow(/odd y/i);
  });

  it("round-trips an even-y address unchanged", () => {
    const evenAddr = { inPub: NOIR_EVEN, index: 3n };
    const decoded = decodeHisokaAddress(encodeHisokaAddress(evenAddr));
    expect(decoded.inPub[0]).toBe(NOIR_EVEN[0]);
    expect(decoded.inPub[1]).toBe(NOIR_EVEN[1]);
    expect(decoded.index).toBe(3n);
  });
});
