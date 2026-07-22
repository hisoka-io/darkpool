import { describe, it, expect } from "vitest";
import { Base8, mulPointEscalar, packPoint, Point } from "@zk-kit/baby-jubjub";
import bs58check from "bs58check";
import { isEvenY } from "../note/keys";
import { decodeHisokaAddress, encodeHisokaAddress } from "../address";

// BabyJubJub base field == BN254 scalar field. A point's y is the canonical residue in [0, P).
const BN254_P =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const HALF_P = BN254_P >> 1n;

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

// `even` column = actual even_y.nr is_even_y output (nargo #[test]), not a TS restatement; a divergence fails a pair.
const NOIR_SPREAD: ReadonlyArray<readonly [bigint, boolean]> = [
  [0n, true],
  [1n, false],
  [2n, true],
  [3n, false],
  [254n, true],
  [255n, false],
  [256n, true],
  [257n, false],
  [HALF_P - 1n, false],
  [HALF_P, true],
  [HALF_P + 1n, false],
  [BN254_P - 2n, false],
  [BN254_P - 1n, true],
  [NOIR_ODD[1], false],
  [NOIR_EVEN[1], true],
  [NOIR_FIXTURE[1], false],
];

describe("even-y parity KAT (TS isEvenY == Noir even_y.nr)", () => {
  it("agrees with the even_y.nr #[test] verdicts on its exact points", () => {
    expect(isEvenY(NOIR_ODD)).toBe(false);
    expect(isEvenY(NOIR_EVEN)).toBe(true);
    expect(isEvenY(NOIR_FIXTURE)).toBe(false);
  });

  it("matches Noir is_even_y verdicts across a y spread including y near P/2", () => {
    for (const [y, evenY] of NOIR_SPREAD) {
      const pub: Point<bigint> = [1n, y];
      expect(isEvenY(pub)).toBe(evenY);
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
