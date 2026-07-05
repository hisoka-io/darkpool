import { describe, it, expect } from "vitest";
import { Fr } from "@aztec/foundation/fields";
import { computePsi, computeNullifier } from "../note/nullifier.js";

const CEK = new Fr(
  0x1fbbfa289c50b7ded032c85e5faa8b3790afc2fd059fd3d299294ff879a08bdan,
);
const EXPECTED_PSI = new Fr(
  0x0441d9b1006cd55062a6458b5dd1db14869f1a5c8fbc66f73032208c2b109956n,
);
const EXPECTED_NULLIFIER = new Fr(
  0x0ced8160f191dfff5c3432bc36f182188226143b294192021ea754f282075897n,
);

describe("psi + psi-nullifier (Noir parity)", () => {
  it("KAT: psi = Poseidon2(CEK, PSI_DOMAIN)", async () => {
    const psi = await computePsi(CEK);
    expect(psi.equals(EXPECTED_PSI)).toBe(true);
  });

  it("KAT: nullifier = Poseidon2(psi, leaf_index=3)", async () => {
    const psi = await computePsi(CEK);
    const nf = await computeNullifier(psi, new Fr(3n));
    expect(nf.equals(EXPECTED_NULLIFIER)).toBe(true);
  });

  it("non-collision: psi differs from CEK", async () => {
    const psi = await computePsi(CEK);
    expect(psi.equals(CEK)).toBe(false);
  });

  it("distinct leaf indices yield distinct nullifiers for one psi", async () => {
    const psi = await computePsi(CEK);
    const nf3 = await computeNullifier(psi, new Fr(3n));
    const nf4 = await computeNullifier(psi, new Fr(4n));
    expect(nf3.equals(nf4)).toBe(false);
  });
});
