import { describe, it, expect } from "vitest";
import { Fr } from "@aztec/foundation/fields";
import { subOrder } from "@zk-kit/baby-jubjub";
import { toBjjScalar } from "../crypto/index.js";

// Parity with circuit assert_subgroup_scalar: scalars feeding an ECDH/in-circuit mul must be reduced mod subOrder first, or the note is unspendable / the key aliases.
describe("toBjjScalar (BabyJubJub subgroup reduction)", () => {
  it("reduces an over-suborder scalar mod the subgroup order", () => {
    const reduced = toBjjScalar(new Fr(subOrder + 12345n));
    expect(reduced.toBigInt()).toBe(12345n);
    expect(reduced.toBigInt() < subOrder).toBe(true);
  });

  it("leaves an in-range scalar unchanged", () => {
    expect(toBjjScalar(new Fr(789n)).toBigInt()).toBe(789n);
    expect(toBjjScalar(new Fr(subOrder - 1n)).toBigInt()).toBe(subOrder - 1n);
  });

  it("maps the subgroup order itself to zero", () => {
    // subOrder % subOrder == 0; the circuit separately rejects a zero scalar via assert_subgroup_scalar.
    expect(toBjjScalar(new Fr(subOrder)).toBigInt()).toBe(0n);
  });
});
