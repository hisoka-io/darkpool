import { describe, it, expect } from "vitest";
import { Fr } from "@aztec/foundation/fields";
import { Base8, mulPointEscalar, Point } from "@zk-kit/baby-jubjub";
import { deriveCek, wrapCek, unwrapCek } from "../crypto/kem.js";

const COMPLIANCE_PK: Point<bigint> = [
  0x085ed469c9a9f102b6d4f6f909b8ceaf6ca49b39759ac2e0feb7e0aada8b7111n,
  0x245e25ab2bd42f0280a5ade750828dd6868f5225ae798d6b51c676f519c8f4e8n,
];
const EPH = new Fr(456n);
const IN_KEY = new Fr(789n);

const EXPECTED_CEK = new Fr(
  0x1fbbfa289c50b7ded032c85e5faa8b3790afc2fd059fd3d299294ff879a08bdan,
);
const EXPECTED_PAD = new Fr(
  0x028539d0d004555c2229a892bad5421c69d21fea344acc2a92c966ac29f70042n,
);
const EXPECTED_CEK_WRAP = new Fr(
  0x182d1d3732b40259bccbc18575d03e2689a7e570137cde69e637355645707bd8n,
);

describe("KEM: CEK + cek_wrap (Noir parity)", () => {
  const ephPub = mulPointEscalar(Base8, EPH.toBigInt());
  const inPub = mulPointEscalar(Base8, IN_KEY.toBigInt());

  it("KAT: CEK = (eph * C).x", () => {
    expect(deriveCek(EPH, COMPLIANCE_PK).equals(EXPECTED_CEK)).toBe(true);
  });

  it("KAT: cek_wrap = CEK + Poseidon2([(eph*in_pub).x])", async () => {
    const wrapped = await wrapCek(EXPECTED_CEK, EPH, inPub);
    expect(wrapped.equals(EXPECTED_CEK_WRAP)).toBe(true);
  });

  it("ECDH symmetry: sender pad == recipient pad", () => {
    const senderPad = new Fr(mulPointEscalar(inPub, EPH.toBigInt())[0]);
    const recipientPad = new Fr(mulPointEscalar(ephPub, IN_KEY.toBigInt())[0]);
    expect(senderPad.equals(recipientPad)).toBe(true);
    expect(senderPad.equals(EXPECTED_PAD)).toBe(true);
  });

  it("round-trips: unwrap(wrap(CEK)) == CEK without eph", async () => {
    const wrapped = await wrapCek(EXPECTED_CEK, EPH, inPub);
    const recovered = await unwrapCek(wrapped, IN_KEY, ephPub);
    expect(recovered.equals(EXPECTED_CEK)).toBe(true);
  });

  it("rejects a non-subgroup scalar", () => {
    const bad = new Fr(Fr.MODULUS - 1n);
    expect(() => deriveCek(bad, COMPLIANCE_PK)).toThrow();
  });

  it("rejects an off-curve or identity point (matches the in-circuit checks)", () => {
    expect(() => deriveCek(EPH, [1n, 2n] as Point<bigint>)).toThrow();
    expect(() => deriveCek(EPH, [0n, 1n] as Point<bigint>)).toThrow();
  });
});
